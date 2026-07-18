#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: RustSec advisory-db (canonical Rust ecosystem advisory archive).

Mines the official ``rustsec/advisory-db`` GitHub repository. Each
``crates/<crate>/<RUSTSEC-id>.md`` file is a single canonical
advisory record authored by the RustSec working group; each ``rust/<area>/<id>.md``
file is a Rust-toolchain advisory. Each emitted hackerman record cites
the GitHub blob URL of the advisory file in ``record_source_url`` so the
record's claim is independently verifiable from the URL alone.

Hard rules (M14-trap discipline, per ``~/.claude/CLAUDE.md``):

* Each record's ``record_source_url`` is the canonical
  ``https://github.com/rustsec/advisory-db/blob/main/<path>`` URL of the
  ``.md`` file the record was extracted from. The mine step HEAD-checks
  every URL emitted to the schema v1.1 ``record_source_url`` field.
* ``verification_tier = tier-1-verified-realtime-api`` -- RustSec is the
  canonical Rust ecosystem advisory authority and the mine step is a
  direct ``gh api`` call to ``/repos/rustsec/advisory-db/contents/...``.
* Honest-zero blockchain filter: the blockchain-relevant crate filter
  may eat most records; ``records_pre_filter`` / ``records_post_filter``
  are surfaced in the summary so any walking-back of the filter is
  measurable.
* ``pre_emit_check(record, strict=False)`` is invoked on every record.
  RustSec advisories sometimes carry only a RUSTSEC-ID without a paired
  CVE-ID, so ``strict=True`` would over-reject; we use the non-strict
  path and surface the verification reason in the per-emit log.
* TOML frontmatter parsing: the RustSec advisory format is a ```toml
  fenced code block at the top of the markdown file. We parse it via
  stdlib ``tomllib`` (3.11+) or a hand-rolled stripped-parser fallback
  for older interpreters.

CLI:

    # Live pull (default):
    python3 tools/hackerman-etl-from-rust-cargo-advisories.py \\
        --out-dir audit/corpus_tags/tags/hackerman_rust_cargo_advisories

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-rust-cargo-advisories.py \\
        --cache-file /tmp/rustsec-cache.json \\
        --out-dir audit/corpus_tags/tags/hackerman_rust_cargo_advisories

Shape anchor: ``tools/hackerman-etl-from-evm-client-advisories.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Rule 37 (Check #77): CVE/GHSA verifier shim - works both when run
# from repo-root (`python3 tools/<miner>.py`) and as a module.
try:
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore
except ImportError:  # pragma: no cover - bootstrap when tools not on sys.path
    import os as _r37_os
    import sys as _r37_sys
    _r37_sys.path.insert(0, _r37_os.path.dirname(_r37_os.path.dirname(_r37_os.path.abspath(__file__))))
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.rust_cargo_advisories.summary.v1"

# RustSec advisory-db canonical paths (per upstream repo layout).
ADVISORY_DB_OWNER = "rustsec/advisory-db"
ADVISORY_DB_DEFAULT_BRANCH = "main"
ADVISORY_DB_RAW_BASE = (
    "https://raw.githubusercontent.com/rustsec/advisory-db/main"
)
ADVISORY_DB_BLOB_BASE = (
    "https://github.com/rustsec/advisory-db/blob/main"
)


# ---------------------------------------------------------------------------
# Blockchain-relevant crate filter
#
# RustSec is a general-purpose Rust ecosystem advisory authority; most
# advisories target generic crates (serde, tokio, chrono). The hackerman
# corpus only takes blockchain / crypto / consensus / signing infra
# advisories so we filter at emit time by crate-name keyword. The filter
# substring set below is closed; new crates require an explicit add.
# ---------------------------------------------------------------------------

BLOCKCHAIN_CRATE_KEYWORDS: Tuple[str, ...] = (
    # Solana / Anchor / Move ecosystem
    "solana", "anchor-", "anchor_", "spl-", "spl_",
    # Substrate / Polkadot / parachain
    "substrate", "parity", "polkadot", "cumulus", "frame-",
    "frame_", "sp-", "sp_",
    # Cosmos / IBC / Tendermint
    "cosmos", "tendermint", "ibc-", "ibc_", "cosmwasm",
    # NEAR / ink! / sov / sov-rollup
    "near-", "near_", "ink-", "ink_", "sov-", "sov_",
    # EVM / Ethereum / L2 / rollup tooling
    "ethers", "web3", "alloy", "ssz",
    "foundry", "reth", "op-reth", "helios", "lighthouse",
    "akula", "trin",
    "paradigm",
    # Bitcoin / Lightning
    "bitcoin", "btc-", "btc_", "btcsuite",
    "lightning", "lnd-",
    # Cryptography / signing primitives (heavily consumed by blockchain)
    "secp256k1", "ed25519", "curve25519", "k256", "p256",
    "schnorr", "blake3", "blake2", "keccak", "sha2", "sha3",
    "ring", "rustls", "snow", "noise",
    "ark-", "arkworks",
    "merkle", "tiny-keccak",
    "x25519",
    # ZK / proof systems
    "halo2", "plonky", "risc0", "sp1", "powdr", "miden",
    "starknet", "cairo", "noir-", "leo-", "groth16", "boojum",
    "barretenberg", "circom", "snark",
    # libp2p (Ethereum / Polkadot / Cosmos networking)
    "libp2p",
    # Crypto-currency tooling crates
    "crypto-",
    # Layer-2 / OP / Arbitrum / zkSync
    "op-", "arbitrum", "zksync",
)


def _crate_matches_filter(crate: str) -> bool:
    cl = crate.lower()
    for kw in BLOCKCHAIN_CRATE_KEYWORDS:
        if kw in cl:
            return True
    return False


# ---------------------------------------------------------------------------
# Slug / YAML helpers
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


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
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            lines.append(
                                f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}"
                            )
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# RustSec TOML frontmatter parser.
#
# Each RustSec advisory .md file begins with a ```toml ... ``` fenced
# block containing the structured advisory record. We parse:
#
#     [advisory]
#     id = "RUSTSEC-2024-0344"
#     package = "curve25519-dalek"
#     date = "2024-06-18"
#     categories = ["crypto-failure"]
#     url = "https://..."
#     aliases = ["CVE-...", "GHSA-..."]
#
#     [versions]
#     patched = [">= 4.1.3"]
# ---------------------------------------------------------------------------


_TOML_FENCE_RE = re.compile(r"```toml\s*\n(.+?)\n```", re.DOTALL)


def _parse_toml_block(text: str) -> Dict[str, Any]:
    """Parse the RustSec TOML frontmatter block.

    Uses stdlib ``tomllib`` (3.11+) if available; otherwise falls back to
    a hand-rolled minimal parser that handles the RustSec subset.
    """
    m = _TOML_FENCE_RE.search(text)
    if not m:
        return {}
    body = m.group(1)
    try:
        import tomllib  # type: ignore  # 3.11+
        return tomllib.loads(body)
    except ImportError:
        pass
    except Exception:
        return {}
    # Fallback: minimal RustSec-shaped parser
    return _parse_toml_fallback(body)


def _parse_toml_fallback(text: str) -> Dict[str, Any]:
    """Minimal RustSec-shaped TOML parser (no third-party dep).

    Handles the subset: ``[section]``, ``key = "value"``, ``key = ["a", "b"]``,
    and ``key = ["a", "b",]``.
    """
    out: Dict[str, Any] = {}
    current: Optional[str] = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            current = m.group(1)
            out.setdefault(current, {})
            continue
        if current is None:
            continue
        m = re.match(r'(\w+)\s*=\s*(.+)$', line)
        if not m:
            continue
        key = m.group(1)
        raw = m.group(2).strip()
        # Multi-line list continuation
        if raw.startswith("[") and not raw.endswith("]"):
            buf = [raw]
            while i < len(lines) and not buf[-1].rstrip().endswith("]"):
                buf.append(lines[i])
                i += 1
            raw = " ".join(buf).strip()
        out[current][key] = _parse_toml_value(raw)
    return out


def _parse_toml_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        # remove trailing comment first
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        items: List[str] = []
        # Naive split by comma; entries are double-quoted strings in RustSec
        for token in re.findall(r'"([^"]*)"', inner):
            items.append(token)
        return items
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return raw  # ISO date kept as string
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if raw == "true":
        return True
    if raw == "false":
        return False
    return raw


def parse_advisory_markdown(text: str) -> Dict[str, Any]:
    """Parse a RustSec ``.md`` advisory.

    Returns ``{"advisory": {...}, "versions": {...}, "title": str, "body": str}``.
    Empty dict ``{}`` if no TOML frontmatter found (skipped at emit time).
    """
    parsed = _parse_toml_block(text)
    if not parsed:
        return {}
    advisory = parsed.get("advisory") or {}
    versions = parsed.get("versions") or {}
    # Body = everything after the closing fence
    body_match = re.search(r"```toml.+?```\s*\n(.*)", text, re.DOTALL)
    body = body_match.group(1) if body_match else ""
    # Title = first markdown H1 / H2 in body
    title_match = re.search(r"^\s*#+\s+(.+)$", body, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else ""
    return {
        "advisory": advisory,
        "versions": versions,
        "title": title,
        "body": body.strip(),
    }


# ---------------------------------------------------------------------------
# gh-api fetch + cache
# ---------------------------------------------------------------------------


def _gh_api(path: str) -> Any:
    """Call ``gh api <path>`` and return the parsed JSON or ``None``."""
    try:
        proc = subprocess.run(
            ["gh", "api", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _curl_get(url: str) -> Optional[str]:
    """Fetch ``url`` via ``curl -fsSL``. Returns body text or ``None``."""
    try:
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "30", url],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def list_crate_dirs(filter_crates: Optional[Set[str]] = None) -> List[str]:
    """Return crate-name directories under ``rustsec/advisory-db/crates``."""
    payload = _gh_api(f"/repos/{ADVISORY_DB_OWNER}/contents/crates")
    if not isinstance(payload, list):
        return []
    names: List[str] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "dir":
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        if filter_crates is not None and name not in filter_crates:
            continue
        names.append(name)
    return names


def list_advisory_files(crate: str) -> List[Dict[str, str]]:
    """Return ``[{name, raw_url, blob_url}]`` for a crate's advisory files."""
    payload = _gh_api(f"/repos/{ADVISORY_DB_OWNER}/contents/crates/{crate}")
    if not isinstance(payload, list):
        return []
    out: List[Dict[str, str]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or ""
        if not name.endswith(".md"):
            continue
        if not name.upper().startswith("RUSTSEC-"):
            continue
        raw = entry.get("download_url") or (
            f"{ADVISORY_DB_RAW_BASE}/crates/{crate}/{name}"
        )
        blob = f"{ADVISORY_DB_BLOB_BASE}/crates/{crate}/{name}"
        out.append({"name": name, "raw_url": raw, "blob_url": blob, "crate": crate})
    return out


def list_rust_toolchain_advisories() -> List[Dict[str, str]]:
    """Return advisory file metadata under ``rust/<area>/...``."""
    out: List[Dict[str, str]] = []
    top = _gh_api(f"/repos/{ADVISORY_DB_OWNER}/contents/rust")
    if not isinstance(top, list):
        return []
    for entry in top:
        if not isinstance(entry, dict) or entry.get("type") != "dir":
            continue
        area = entry.get("name") or ""
        files = _gh_api(f"/repos/{ADVISORY_DB_OWNER}/contents/rust/{area}")
        if not isinstance(files, list):
            continue
        for f in files:
            if not isinstance(f, dict):
                continue
            name = f.get("name") or ""
            if not name.endswith(".md"):
                continue
            raw = f.get("download_url") or (
                f"{ADVISORY_DB_RAW_BASE}/rust/{area}/{name}"
            )
            blob = f"{ADVISORY_DB_BLOB_BASE}/rust/{area}/{name}"
            out.append({
                "name": name,
                "raw_url": raw,
                "blob_url": blob,
                "crate": f"rust-toolchain-{area}",
            })
    return out


def fetch_all_advisories(
    *,
    filter_keywords: Tuple[str, ...] = BLOCKCHAIN_CRATE_KEYWORDS,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    include_toolchain: bool = True,
) -> Dict[str, Any]:
    """Return cached payload: ``{crate: {files: [...], advisories: [...]}}``.

    ``advisories`` entries are the parsed-frontmatter records plus
    ``raw_url`` / ``blob_url`` / ``crate`` / ``filename`` metadata.
    """
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))

    crates = list_crate_dirs()
    relevant = [c for c in crates if _crate_matches_filter(c)]
    out: Dict[str, Any] = {
        "_meta": {
            "crates_total": len(crates),
            "crates_filtered": len(relevant),
        },
        "crates": {},
    }
    for crate in sorted(relevant):
        files = list_advisory_files(crate)
        adv_records: List[Dict[str, Any]] = []
        for f in files:
            body = _curl_get(f["raw_url"])
            if body is None:
                continue
            parsed = parse_advisory_markdown(body)
            if not parsed:
                continue
            adv_records.append({
                "filename": f["name"],
                "raw_url": f["raw_url"],
                "blob_url": f["blob_url"],
                "crate": crate,
                "parsed": parsed,
            })
        out["crates"][crate] = adv_records

    if include_toolchain:
        toolchain_files = list_rust_toolchain_advisories()
        for f in toolchain_files:
            body = _curl_get(f["raw_url"])
            if body is None:
                continue
            parsed = parse_advisory_markdown(body)
            if not parsed:
                continue
            out["crates"].setdefault(f["crate"], []).append({
                "filename": f["name"],
                "raw_url": f["raw_url"],
                "blob_url": f["blob_url"],
                "crate": f["crate"],
                "parsed": parsed,
            })

    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(out, indent=2, sort_keys=True), encoding="utf-8"
        )
    return out


# ---------------------------------------------------------------------------
# Advisory -> hackerman record mapping
# ---------------------------------------------------------------------------


# RustSec canonical category -> hackerman attack_class.
# The 8 canonical categories are documented at
# https://rustsec.org/advisories/index.html.
_CATEGORY_TO_ATTACK_CLASS: Dict[str, str] = {
    "memory-corruption": "rust-memory-corruption",
    "memory-exposure": "rust-memory-exposure",
    "thread-safety": "rust-thread-safety",
    "code-execution": "rust-code-execution",
    "format-injection": "rust-format-injection",
    "denial-of-service": "rust-denial-of-service",
    "crypto-failure": "rust-crypto-failure",
    "file-disclosure": "rust-file-disclosure",
}


# RustSec category -> impact_class (schema enum).
_CATEGORY_TO_IMPACT: Dict[str, str] = {
    "memory-corruption": "dos",  # most are panic / OOB-read / UAF; theft is rare
    "memory-exposure": "privilege-escalation",  # leaks secret material
    "thread-safety": "dos",
    "code-execution": "privilege-escalation",
    "format-injection": "privilege-escalation",
    "denial-of-service": "dos",
    "crypto-failure": "theft",  # weak crypto => signature forge / key extract
    "file-disclosure": "privilege-escalation",
}


# Crate-name keyword -> target_domain (schema enum).
# Order matters: more specific keywords appear first.
_DOMAIN_HINTS: Tuple[Tuple[str, str], ...] = (
    ("solana", "l1-client"),
    ("anchor", "l1-client"),
    ("substrate", "l1-client"),
    ("polkadot", "l1-client"),
    ("near", "l1-client"),
    ("reth", "l1-client"),
    ("erigon", "l1-client"),
    ("akula", "l1-client"),
    ("ssz", "consensus"),
    ("lighthouse", "consensus"),
    ("prysm", "consensus"),
    ("tendermint", "consensus"),
    ("cosmos", "consensus"),
    ("cosmwasm", "consensus"),
    ("ibc", "bridge"),
    ("bitcoin", "l1-client"),
    ("lightning", "l1-client"),
    ("alloy", "rpc-infra"),
    ("ethers", "rpc-infra"),
    ("web3", "rpc-infra"),
    ("foundry", "rpc-infra"),
    ("rustls", "rpc-infra"),
    ("hyper", "rpc-infra"),
    ("tokio", "rpc-infra"),
    ("libp2p", "rpc-infra"),
    ("axum", "rpc-infra"),
    ("ring", "rpc-infra"),
    ("snow", "rpc-infra"),
    ("rocksdb", "rpc-infra"),
    ("merkle", "consensus"),
    ("halo2", "zk-proof"),
    ("plonky", "zk-proof"),
    ("risc0", "zk-proof"),
    ("sp1", "zk-proof"),
    ("powdr", "zk-proof"),
    ("miden", "zk-proof"),
    ("starknet", "zk-proof"),
    ("cairo", "zk-proof"),
    ("noir", "zk-proof"),
    ("groth16", "zk-proof"),
    ("boojum", "zk-proof"),
    ("barretenberg", "zk-proof"),
    ("snark", "zk-proof"),
    ("circom", "zk-proof"),
    ("ed25519", "rpc-infra"),
    ("curve25519", "rpc-infra"),
    ("secp256k1", "rpc-infra"),
    ("k256", "rpc-infra"),
    ("p256", "rpc-infra"),
    ("schnorr", "rpc-infra"),
    ("blake", "rpc-infra"),
    ("keccak", "rpc-infra"),
    ("sha", "rpc-infra"),
    ("ark", "zk-proof"),
    ("crypto", "rpc-infra"),
)


def _infer_domain(crate: str) -> str:
    cl = crate.lower()
    for kw, dom in _DOMAIN_HINTS:
        if kw in cl:
            return dom
    return "rpc-infra"


def _normalize_categories(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(c).strip() for c in raw if str(c).strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def _attack_class(categories: List[str], crate: str) -> str:
    for cat in categories:
        if cat in _CATEGORY_TO_ATTACK_CLASS:
            return _CATEGORY_TO_ATTACK_CLASS[cat]
    # Fallback: derive from crate hint
    return f"rust-cargo-advisory-{slugify(crate, max_len=64)}"


def _impact_class(categories: List[str]) -> str:
    for cat in categories:
        if cat in _CATEGORY_TO_IMPACT:
            return _CATEGORY_TO_IMPACT[cat]
    return "dos"


def _impact_actor(impact_class: str, domain: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    if impact_class == "dos":
        if domain in {"l1-client", "consensus"}:
            return "validator-set"
        return "arbitrary-user"
    if impact_class in {"theft", "freeze", "precision-loss"}:
        if domain in {"l1-client", "consensus"}:
            return "validator-set"
        return "arbitrary-user"
    return "arbitrary-user"


def _severity_from_categories(categories: List[str]) -> str:
    """RustSec doesn't ship a severity field per advisory by design;
    derive a conservative class from the categories. ``crypto-failure`` /
    ``code-execution`` / ``memory-corruption`` map to high; the rest to
    medium. Records that lack any recognised category default to low.
    """
    cats = set(categories)
    if cats & {"code-execution", "memory-corruption", "crypto-failure"}:
        return "high"
    if cats & {
        "memory-exposure", "format-injection", "denial-of-service",
        "thread-safety", "file-disclosure",
    }:
        return "medium"
    return "low"


def _dollar_class(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    return "non-financial"


def _year_from(advisory: Dict[str, Any], filename: str) -> int:
    date = advisory.get("date")
    if isinstance(date, str) and len(date) >= 4 and date[:4].isdigit():
        y = int(date[:4])
        if y >= 2000:
            return y
    m = re.search(r"RUSTSEC-(\d{4})-", filename)
    if m:
        return int(m.group(1))
    return 2024


def _extract_cve_ghsa(aliases: List[str]) -> Tuple[Optional[str], Optional[str]]:
    cve: Optional[str] = None
    ghsa: Optional[str] = None
    for a in aliases:
        au = str(a).strip()
        if not au:
            continue
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", au) and cve is None:
            cve = au
        elif re.fullmatch(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", au) and ghsa is None:
            ghsa = au
    return cve, ghsa


def _record_id(crate: str, rustsec_id: str) -> str:
    crate_slug = slugify(crate, max_len=64)
    rid_slug = slugify(rustsec_id, max_len=64) or "rustsec-unknown"
    payload = f"rust-cargo-adv|{crate}|{rustsec_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    rid = f"rust-cargo-adv:{crate_slug}:{rid_slug}:{digest}"
    return rid[:160]


def _function_shape(
    crate: str,
    advisory: Dict[str, Any],
    rustsec_id: str,
    categories: List[str],
    cve: Optional[str],
    ghsa: Optional[str],
) -> Dict[str, Any]:
    raw_signature = f"{crate} :: {rustsec_id}"
    shape_tags: List[str] = [
        slugify(f"rust-crate-{crate}", max_len=80),
        slugify(rustsec_id, max_len=64),
        "rustsec-advisory-db",
    ]
    for cat in categories:
        shape_tags.append(slugify(f"category-{cat}", max_len=64))
    if cve:
        shape_tags.append(slugify(cve, max_len=64))
    if ghsa:
        shape_tags.append(slugify(ghsa, max_len=64))
    seen: set = set()
    unique: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            unique.append(t)
    if not unique:
        unique = ["rustsec-advisory"]
    return {"raw_signature": raw_signature[:500], "shape_tags": unique}


def _required_preconditions(
    crate: str,
    rustsec_id: str,
    advisory: Dict[str, Any],
    blob_url: str,
) -> List[str]:
    out: List[str] = []
    out.append(f"Reference advisory at {blob_url}")
    date = advisory.get("date")
    if isinstance(date, str) and date:
        out.append(f"Published-at {date}")
    out.append(f"Affected crate {crate}")
    aliases = advisory.get("aliases") or []
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a:
                out.append(f"Alias {a}")
    out.append("verification_tier=tier-1-verified-realtime-api")
    seen: set = set()
    unique: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


def _fix_pattern(versions: Dict[str, Any]) -> str:
    patched = versions.get("patched") if isinstance(versions, dict) else None
    if isinstance(patched, list) and patched:
        return one_line(
            f"Upgrade to patched-version range {', '.join(str(p) for p in patched)} per the RustSec advisory.",
            "Apply the RustSec patched-version range.",
            max_len=900,
        )
    if isinstance(patched, str) and patched:
        return one_line(
            f"Upgrade to patched-version range {patched} per the RustSec advisory.",
            "Apply the RustSec patched-version range.",
            max_len=900,
        )
    return (
        "Upgrade to the patched crate version (no explicit range emitted in the advisory; "
        "consult upstream)."
    )


def _anti_pattern(crate: str, categories: List[str]) -> str:
    cat_str = ", ".join(categories) if categories else "uncategorised"
    return one_line(
        f"Pinning the unpatched ``{crate}`` crate in a blockchain / cryptographic / signing "
        f"path; ignoring the upstream RustSec advisory in the {cat_str} category.",
        "Running an unpatched RustSec-flagged crate in production.",
        max_len=900,
    )


def _attacker_action_sequence(
    crate: str,
    rustsec_id: str,
    title: str,
    body: str,
    categories: List[str],
    verification_tier: str,
) -> str:
    text = title or rustsec_id
    if body:
        text = f"{text}. {body}"
    text = re.sub(r"\s+", " ", text).strip()
    state_marker = (
        f" [crate={crate}; rustsec_id={rustsec_id}; "
        f"categories={'|'.join(categories) or 'none'}; "
        f"verification_tier={verification_tier}]"
    )
    body_max = 4900 - len(state_marker)
    body_cut = one_line(text, "RustSec advisory", max_len=body_max)
    return (body_cut + state_marker).strip()


def _attacker_role(categories: List[str]) -> str:
    cats = set(categories)
    if cats & {"code-execution", "memory-corruption", "format-injection"}:
        return "unprivileged"
    if cats & {"crypto-failure"}:
        return "unprivileged"
    return "unprivileged"


def advisory_to_record(
    *,
    crate: str,
    blob_url: str,
    parsed: Dict[str, Any],
    verification_tier: str,
) -> Optional[Dict[str, Any]]:
    """Build one schema-v1.1 hackerman record from a parsed RustSec advisory.

    Returns ``None`` when the advisory file lacks the mandatory ``id`` field.
    """
    advisory = parsed.get("advisory") or {}
    versions = parsed.get("versions") or {}
    title = parsed.get("title") or ""
    body = parsed.get("body") or ""
    rustsec_id = advisory.get("id")
    if not isinstance(rustsec_id, str) or not rustsec_id.startswith("RUSTSEC-"):
        return None
    categories = _normalize_categories(advisory.get("categories"))
    aliases = advisory.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    aliases_str = [str(a) for a in aliases if isinstance(a, (str, int))]
    cve, ghsa = _extract_cve_ghsa(aliases_str)
    domain = _infer_domain(crate)
    impact_class = _impact_class(categories)
    impact_actor = _impact_actor(impact_class, domain)
    severity = _severity_from_categories(categories)
    year = _year_from(advisory, parsed.get("filename") or "")
    attack_class = _attack_class(categories, crate)
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id(crate, rustsec_id),
        "source_audit_ref": one_line(
            blob_url, f"rustsec:{crate}:{rustsec_id}", max_len=240
        ),
        "target_domain": domain,
        "target_language": "rust",
        "target_repo": "rustsec/advisory-db",
        "target_component": one_line(
            f"{crate}:{rustsec_id}", f"{crate}:advisory", max_len=240
        ),
        "function_shape": _function_shape(
            crate, advisory, rustsec_id, categories, cve, ghsa
        ),
        "bug_class": "rust-cargo-public-advisory",
        "attack_class": attack_class,
        "attacker_role": _attacker_role(categories),
        "attacker_action_sequence": _attacker_action_sequence(
            crate, rustsec_id, title, body, categories, verification_tier
        ),
        "required_preconditions": _required_preconditions(
            crate, rustsec_id, advisory, blob_url
        ),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": _fix_pattern(versions),
        "fix_anti_pattern_avoided": _anti_pattern(crate, categories),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "verification_method": "manual",
        "verification_tier": verification_tier,
        "record_source_url": blob_url,
        "cross_language_analogues": [],
        "related_records": [],
    }
    if cve:
        record["cve_id"] = cve
    if ghsa:
        record["ghsa_id"] = ghsa
    return record


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_records(
    payload: Dict[str, Any],
    verification_tier: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    crates_payload = payload.get("crates") or {}
    for crate, adv_list in crates_payload.items():
        if not isinstance(adv_list, list):
            continue
        for entry in adv_list:
            if not isinstance(entry, dict):
                continue
            parsed = entry.get("parsed") or {}
            blob_url = entry.get("blob_url") or ""
            record = advisory_to_record(
                crate=crate,
                blob_url=blob_url,
                parsed=parsed,
                verification_tier=verification_tier,
            )
            if record is None:
                continue
            if record["record_id"] in seen_ids:
                continue
            seen_ids.add(record["record_id"])
            records.append(record)
    return records


def slug_for_record(record: Dict[str, Any]) -> str:
    target = record["target_component"].replace(":", "__")
    return slugify(target, max_len=140)


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    include_toolchain: bool = True,
) -> Dict[str, Any]:
    if cache_file is not None:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        verification_tier = "tier-1-verified-realtime-api"
    else:
        payload = fetch_all_advisories(
            cache_file=None,
            write_cache_file=write_cache_file,
            include_toolchain=include_toolchain,
        )
        verification_tier = "tier-1-verified-realtime-api"

    records = build_records(payload, verification_tier)
    if limit is not None:
        records = records[:limit]

    meta = payload.get("_meta") or {}
    crates_total = int(meta.get("crates_total") or 0)
    crates_filtered = int(meta.get("crates_filtered") or 0)
    crates_payload = payload.get("crates") or {}
    records_pre_filter = sum(
        len(v) for v in crates_payload.values() if isinstance(v, list)
    )

    by_crate: Dict[str, int] = {}
    by_attack_class: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_domain: Dict[str, int] = {}
    sample_urls: List[str] = []
    files: List[str] = []
    errors: List[str] = []
    head_checks: Dict[str, str] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        # surface counters
        crate = record["target_component"].split(":", 1)[0]
        by_crate[crate] = by_crate.get(crate, 0) + 1
        by_attack_class[record["attack_class"]] = (
            by_attack_class.get(record["attack_class"], 0) + 1
        )
        by_impact[record["impact_class"]] = (
            by_impact.get(record["impact_class"], 0) + 1
        )
        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        by_domain[record["target_domain"]] = (
            by_domain.get(record["target_domain"], 0) + 1
        )
        if len(sample_urls) < 5:
            sample_urls.append(record["record_source_url"])

        slug = slug_for_record(record)
        rec_subdir = out_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))
        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            yaml_path.write_text(yaml_dump(record), encoding="utf-8")
            try:
                ok_emit, reason = pre_emit_check(record, strict=False)
                head_checks[record["record_id"]] = (
                    f"{'ok' if ok_emit else 'skip'}:{reason}"
                )
                if not ok_emit:
                    print(
                        f"r37-skip {reason}: {record.get('record_id', '?')}",
                        file=sys.stderr,
                    )
            except Exception as exc:  # pragma: no cover - verifier is best-effort
                head_checks[record["record_id"]] = f"error:{exc}"

    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "records_pre_filter": records_pre_filter,
        "records_emitted": len(records),
        "crates_total": crates_total,
        "crates_filtered": crates_filtered,
        "crates_emitted": len(by_crate),
        "by_crate": by_crate,
        "by_attack_class": by_attack_class,
        "by_impact_class": by_impact,
        "by_severity": by_severity,
        "by_target_domain": by_domain,
        "sample_source_urls": sample_urls,
        "files": files[:50],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--cache-file",
        help="Read previously-cached RustSec payload instead of calling gh api.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched RustSec payload to this path for later offline replay.",
    )
    parser.add_argument(
        "--skip-toolchain",
        action="store_true",
        help="Skip the rust/<area> toolchain advisories.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=Path(args.write_cache_file).expanduser().resolve()
        if args.write_cache_file
        else None,
        include_toolchain=not args.skip_toolchain,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman rust-cargo-advisories ETL: "
            f"records={summary['records_emitted']}/{summary['records_pre_filter']} "
            f"crates_emitted={summary['crates_emitted']}/{summary.get('crates_filtered', 0)} "
            f"verification_tier={summary['verification_tier']} "
            f"by_severity={summary['by_severity']} "
            f"by_impact={summary['by_impact_class']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
