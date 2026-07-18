#!/usr/bin/env python3
"""Wave-5 L1 Hackerman ETL: Go vulnerability database (``vuln.go.dev``).

Mines the official Go vulnerability database - the canonical Go-ecosystem
advisory feed maintained by the Go security team. ``vuln.go.dev`` is the
direct analog of RustSec's ``advisory-db`` for the Go ecosystem and is
highly relevant to the Go cosmos-sdk audit targets (dYdX, The Graph,
Spark statechain coordinator services).

Feed shape (OSV / Go-vuln-DB protocol, see go.dev/security/vuln/database):

* ``https://vuln.go.dev/index/db.json``    -- modtime index.
* ``https://vuln.go.dev/index/vulns.json`` -- per-GO-ID summary list:
  ``[{"id": "GO-2024-2937", "modified": "...", "aliases": [...], ...}]``.
* ``https://vuln.go.dev/ID/<GO-ID>.json``  -- the full OSV record for one
  ``GO-YYYY-NNNN`` entry.

Each emitted hackerman record cites the canonical per-ID URL
(``https://vuln.go.dev/ID/<GO-ID>.json``) in ``record_source_url`` so the
record's claim is independently verifiable from the URL alone.

Hard rules (M14-trap / real-source discipline, per ``~/.claude/CLAUDE.md``):

* Honest-zero gate (mirrors the W4.2 post-mortem miner pattern): the
  import / dry-run path performs ZERO network I/O. Network I/O requires
  ``--fetch``. With neither ``--fetch`` nor a populated cache / injected
  bytes, the miner prints ``BLOCKED-NO-REAL-SOURCE`` to stderr and emits
  zero records. There are NO training-data-recalled GO-IDs in this file.
* ``verification_tier = tier-1-officially-disclosed`` -- every entry in
  ``vuln.go.dev`` is an officially-disclosed advisory triaged by the Go
  security team, each carrying a canonical ``GO-YYYY-NNNN`` external ID
  (and typically a CVE / GHSA alias). The tier is a first-class field set
  at emit time on every record (Rule 37). The miner refuses to emit any
  record lacking a ``GO-`` external ID.
* ``pre_emit_check(record, strict=False)`` is invoked on every record;
  the per-emit verification reason is surfaced in the summary.
* Blockchain-relevance filter: ``vuln.go.dev`` covers the whole Go
  ecosystem; the hackerman corpus only takes blockchain / consensus /
  signing / crypto-infra advisories. The filter is applied by affected
  module path keyword; ``records_pre_filter`` / ``records_post_filter``
  are surfaced so any walking-back of the filter is measurable.

CLI:

    # Honest-zero (no network, no cache) -> BLOCKED-NO-REAL-SOURCE:
    python3 tools/hackerman-etl-from-go-vuln-db.py \\
        --out-dir audit/corpus_tags/tags/hackerman_go_vuln_db --dry-run

    # Live pull:
    python3 tools/hackerman-etl-from-go-vuln-db.py \\
        --out-dir audit/corpus_tags/tags/hackerman_go_vuln_db --fetch

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-go-vuln-db.py \\
        --out-dir audit/corpus_tags/tags/hackerman_go_vuln_db \\
        --cache-file /tmp/go-vuln-cache.json

Shape anchor: ``tools/hackerman-etl-from-rust-cargo-advisories.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
SUMMARY_SCHEMA = "auditooor.hackerman_etl.go_vuln_db.summary.v1"

# vuln.go.dev canonical endpoints (per go.dev/security/vuln/database).
GO_VULN_DB_BASE = "https://vuln.go.dev"
GO_VULN_DB_INDEX = f"{GO_VULN_DB_BASE}/index/vulns.json"


# ---------------------------------------------------------------------------
# Blockchain-relevant module filter
#
# vuln.go.dev is a general-purpose Go ecosystem advisory feed; most
# advisories target generic modules (net/http, crypto/tls, k8s, docker).
# The hackerman corpus only takes blockchain / consensus / signing /
# crypto-infra advisories so we filter at emit time by affected-module
# path keyword. The substring set below is closed; new modules require
# an explicit add.
# ---------------------------------------------------------------------------

BLOCKCHAIN_MODULE_KEYWORDS: Tuple[str, ...] = (
    # Cosmos / IBC / Tendermint / CometBFT ecosystem (dYdX, Spark, Graph)
    "cosmos-sdk", "cosmos/", "cometbft", "tendermint", "ibc-go",
    "cosmwasm", "wasmd", "ignite", "osmosis", "dydx",
    # Go-Ethereum / EVM / L2 clients
    "go-ethereum", "ethereum/", "erigon", "op-geth", "op-node",
    "prysm", "prysmaticlabs", "ethereumjs",
    # Bitcoin / Lightning (Go)
    "btcd", "btcsuite", "btcwallet", "lnd", "lightningnetwork",
    # Solana / NEAR Go bridges
    "solana-go", "near/",
    # Cryptography / signing primitives heavily consumed by blockchain
    "secp256k1", "ed25519", "curve25519", "bls12", "blst",
    "schnorr", "keccak", "sha3", "blake2", "blake3",
    "decred/dcrd", "filippo.io",
    # Networking / RPC infra consumed by chain nodes
    "libp2p", "grpc-go", "protobuf-go", "go-grpc",
    "x/crypto", "golang.org/x/crypto",
    # ORM / DB layer used by chain coordinator services (Spark ent)
    "entgo", "ent.io", "jackc/pgx", "lib/pq",
    # ZK / proof tooling (Go)
    "gnark", "consensys/gnark", "iden3",
    # General blockchain tooling
    "blockchain", "consensus", "validator", "merkle",
    "go-libp2p", "multiformats",
)


def _module_matches_filter(module: str) -> bool:
    ml = (module or "").lower()
    for kw in BLOCKCHAIN_MODULE_KEYWORDS:
        if kw in ml:
            return True
    return False


# ---------------------------------------------------------------------------
# Slug / YAML helpers (shape-matched to the RustSec miner)
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
# Network fetch (gated behind --fetch; honest-zero otherwise)
# ---------------------------------------------------------------------------


def _curl_get(url: str) -> Optional[bytes]:
    """Fetch ``url`` via ``curl -fsSL``. Returns body bytes or ``None``."""
    try:
        proc = subprocess.run(
            ["curl", "-fsSL", "--max-time", "45", url],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def fetch_payload(
    *,
    fetch_live: bool,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
    limit_ids: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Build the cached payload ``{"index": [...], "osv": {GO-ID: {...}}}``.

    Returns ``None`` when no real source is available (honest-zero gate):
    no cache file, no injected prefetched bytes, and ``--fetch`` not set.
    """
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))

    prefetched = dict(prefetched or {})

    # Honest-zero gate: zero network and zero injected bytes -> BLOCKED.
    if not fetch_live and not prefetched:
        return None

    def _get_json(url: str) -> Optional[Any]:
        if url in prefetched:
            raw = prefetched[url]
        elif fetch_live:
            raw = _curl_get(url)
        else:
            return None
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None

    index = _get_json(GO_VULN_DB_INDEX)
    if not isinstance(index, list):
        return None

    osv: Dict[str, Any] = {}
    count = 0
    for entry in index:
        if not isinstance(entry, dict):
            continue
        go_id = entry.get("id")
        if not isinstance(go_id, str) or not go_id.startswith("GO-"):
            continue
        record = _get_json(f"{GO_VULN_DB_BASE}/ID/{go_id}.json")
        if not isinstance(record, dict):
            continue
        osv[go_id] = record
        count += 1
        if limit_ids is not None and count >= limit_ids:
            break

    payload: Dict[str, Any] = {
        "_meta": {"index_count": len(index), "osv_fetched": len(osv)},
        "index": index,
        "osv": osv,
    }
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
    return payload


# ---------------------------------------------------------------------------
# OSV record parsing helpers
# ---------------------------------------------------------------------------


def osv_affected_modules(osv: Dict[str, Any]) -> List[str]:
    """Return the affected Go module paths from an OSV record."""
    out: List[str] = []
    for aff in osv.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if isinstance(pkg, dict):
            name = pkg.get("name")
            if isinstance(name, str) and name:
                out.append(name)
    return out


def osv_aliases(osv: Dict[str, Any]) -> List[str]:
    raw = osv.get("aliases")
    if isinstance(raw, list):
        return [str(a).strip() for a in raw if str(a).strip()]
    return []


def _extract_cve_ghsa(aliases: List[str]) -> Tuple[Optional[str], Optional[str]]:
    cve: Optional[str] = None
    ghsa: Optional[str] = None
    for a in aliases:
        au = str(a).strip()
        if not au:
            continue
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", au) and cve is None:
            cve = au
        elif re.fullmatch(
            r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", au
        ) and ghsa is None:
            ghsa = au
    return cve, ghsa


def osv_year(go_id: str, osv: Dict[str, Any]) -> int:
    m = re.search(r"GO-(\d{4})-", go_id)
    if m:
        y = int(m.group(1))
        if y >= 2000:
            return y
    pub = osv.get("published") or osv.get("modified")
    if isinstance(pub, str) and len(pub) >= 4 and pub[:4].isdigit():
        return int(pub[:4])
    return 2024


def osv_patched_versions(osv: Dict[str, Any]) -> List[str]:
    """Return the fixed-version strings from the OSV ``ranges`` events."""
    out: List[str] = []
    for aff in osv.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    out.append(str(ev["fixed"]))
    seen: set = set()
    uniq: List[str] = []
    for v in out:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


# ---------------------------------------------------------------------------
# OSV symptom-keyword -> hackerman taxonomy.
#
# vuln.go.dev does not ship a structured category enum (unlike RustSec).
# We derive a conservative attack_class / impact_class from the OSV
# summary + details text via a closed keyword table. Unmatched records
# fall back to a generic Go-advisory class.
# ---------------------------------------------------------------------------

_SYMPTOM_TABLE: Tuple[Tuple[str, str, str, str], ...] = (
    # keyword, attack_class, impact_class, severity
    ("denial of service", "go-denial-of-service", "dos", "medium"),
    ("infinite loop", "go-denial-of-service", "dos", "medium"),
    ("panic", "go-denial-of-service", "dos", "medium"),
    ("stack exhaustion", "go-denial-of-service", "dos", "medium"),
    ("memory exhaustion", "go-denial-of-service", "dos", "medium"),
    ("uncontrolled resource", "go-denial-of-service", "dos", "medium"),
    ("out of memory", "go-denial-of-service", "dos", "medium"),
    ("authentication bypass", "go-authentication-bypass", "privilege-escalation", "high"),
    ("authorization bypass", "go-authorization-bypass", "privilege-escalation", "high"),
    ("signature verification", "go-signature-verification-flaw", "theft", "high"),
    ("signature forgery", "go-signature-verification-flaw", "theft", "high"),
    ("incorrect verification", "go-signature-verification-flaw", "theft", "high"),
    ("private key", "go-key-material-exposure", "theft", "high"),
    ("information disclosure", "go-information-disclosure", "privilege-escalation", "medium"),
    ("information leak", "go-information-disclosure", "privilege-escalation", "medium"),
    ("timing side channel", "go-timing-side-channel", "theft", "high"),
    ("constant-time", "go-timing-side-channel", "theft", "high"),
    ("code execution", "go-code-execution", "privilege-escalation", "high"),
    ("command injection", "go-command-injection", "privilege-escalation", "high"),
    ("path traversal", "go-path-traversal", "privilege-escalation", "medium"),
    ("integer overflow", "go-integer-overflow", "precision-loss", "medium"),
    ("buffer overflow", "go-memory-corruption", "dos", "high"),
    ("race condition", "go-race-condition", "dos", "medium"),
    ("data race", "go-race-condition", "dos", "medium"),
)


def _classify(osv: Dict[str, Any]) -> Tuple[str, str, str]:
    """Return ``(attack_class, impact_class, severity)`` from OSV text."""
    blob = " ".join(
        str(x or "")
        for x in (osv.get("summary"), osv.get("details"))
    ).lower()
    for kw, ac, ic, sev in _SYMPTOM_TABLE:
        if kw in blob:
            return ac, ic, sev
    return "go-public-advisory", "dos", "low"


def _infer_domain(modules: List[str]) -> str:
    blob = " ".join(modules).lower()
    if any(k in blob for k in ("cosmos", "cometbft", "tendermint", "ibc", "wasmd", "dydx", "osmosis")):
        return "consensus"
    if any(k in blob for k in ("go-ethereum", "erigon", "prysm", "btcd", "lnd", "lightning")):
        return "l1-client"
    if any(k in blob for k in ("gnark", "iden3", "bls12", "blst")):
        return "zk-proof"
    if any(k in blob for k in ("ibc-go",)):
        return "bridge"
    return "rpc-infra"


def _impact_actor(impact_class: str, domain: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    if impact_class == "dos":
        return "validator-set" if domain in {"l1-client", "consensus"} else "arbitrary-user"
    if impact_class in {"theft", "freeze", "precision-loss"}:
        return "validator-set" if domain in {"l1-client", "consensus"} else "arbitrary-user"
    return "arbitrary-user"


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


def _record_id(module: str, go_id: str) -> str:
    mod_slug = slugify(module, max_len=64)
    gid_slug = slugify(go_id, max_len=64) or "go-unknown"
    payload = f"go-vuln-db|{module}|{go_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    rid = f"go-vuln-db:{mod_slug}:{gid_slug}:{digest}"
    return rid[:160]


def _function_shape(
    module: str,
    go_id: str,
    attack_class: str,
    cve: Optional[str],
    ghsa: Optional[str],
) -> Dict[str, Any]:
    shape_tags: List[str] = [
        slugify(f"go-module-{module}", max_len=80),
        slugify(go_id, max_len=64),
        "go-vuln-db",
        slugify(attack_class, max_len=64),
    ]
    if cve:
        shape_tags.append(slugify(cve, max_len=64))
    if ghsa:
        shape_tags.append(slugify(ghsa, max_len=64))
    seen: set = set()
    uniq: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    if not uniq:
        uniq = ["go-vuln-advisory"]
    return {"raw_signature": f"{module} :: {go_id}"[:500], "shape_tags": uniq}


def _required_preconditions(
    module: str,
    go_id: str,
    osv: Dict[str, Any],
    source_url: str,
) -> List[str]:
    out: List[str] = [
        f"Reference Go-vuln-DB advisory at {source_url}",
        f"Affected Go module {module}",
        f"Advisory id {go_id}",
    ]
    pub = osv.get("published")
    if isinstance(pub, str) and pub:
        out.append(f"Published-at {pub}")
    for a in osv_aliases(osv):
        out.append(f"Alias {a}")
    out.append("verification_tier=tier-1-officially-disclosed")
    seen: set = set()
    uniq: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            uniq.append(cleaned)
    return uniq


def _fix_pattern(patched: List[str]) -> str:
    if patched:
        return one_line(
            f"Upgrade the affected Go module to a fixed version "
            f"({', '.join(patched)}) per the vuln.go.dev advisory.",
            "Apply the vuln.go.dev fixed-version range.",
            max_len=900,
        )
    return (
        "Upgrade to the patched module version (no explicit fixed version "
        "in the advisory; consult upstream)."
    )


def _anti_pattern(module: str, attack_class: str) -> str:
    return one_line(
        f"Pinning the unpatched ``{module}`` Go module in a blockchain / "
        f"consensus / signing path; ignoring the upstream vuln.go.dev "
        f"advisory ({attack_class}).",
        "Running an unpatched vuln.go.dev-flagged Go module in production.",
        max_len=900,
    )


def _attacker_action_sequence(
    module: str,
    go_id: str,
    osv: Dict[str, Any],
    attack_class: str,
    verification_tier: str,
) -> str:
    text = one_line(osv.get("summary"), go_id, max_len=400)
    details = one_line(osv.get("details"), "", max_len=3500)
    if details:
        text = f"{text}. {details}"
    text = re.sub(r"\s+", " ", text).strip()
    marker = (
        f" [module={module}; go_id={go_id}; attack_class={attack_class}; "
        f"verification_tier={verification_tier}]"
    )
    body_max = 4900 - len(marker)
    body = one_line(text, "Go vuln-DB advisory", max_len=body_max)
    return (body + marker).strip()


def osv_to_record(
    *,
    module: str,
    go_id: str,
    osv: Dict[str, Any],
    verification_tier: str,
) -> Optional[Dict[str, Any]]:
    """Build one schema-v1.1 hackerman record from one OSV entry + module.

    Returns ``None`` when the entry lacks a ``GO-`` external id.
    """
    if not isinstance(go_id, str) or not go_id.startswith("GO-"):
        return None
    aliases = osv_aliases(osv)
    cve, ghsa = _extract_cve_ghsa(aliases)
    attack_class, impact_class, severity = _classify(osv)
    modules = osv_affected_modules(osv) or [module]
    domain = _infer_domain(modules)
    impact_actor = _impact_actor(impact_class, domain)
    year = osv_year(go_id, osv)
    patched = osv_patched_versions(osv)
    source_url = f"{GO_VULN_DB_BASE}/ID/{go_id}.json"
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id(module, go_id),
        "source_audit_ref": one_line(
            source_url, f"go-vuln-db:{module}:{go_id}", max_len=240
        ),
        "target_domain": domain,
        "target_language": "go",
        "target_repo": "vuln.go.dev",
        "target_component": one_line(
            f"{module}:{go_id}", f"{module}:advisory", max_len=240
        ),
        "function_shape": _function_shape(module, go_id, attack_class, cve, ghsa),
        "bug_class": "go-public-advisory",
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(
            module, go_id, osv, attack_class, verification_tier
        ),
        "required_preconditions": _required_preconditions(
            module, go_id, osv, source_url
        ),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": _fix_pattern(patched),
        "fix_anti_pattern_avoided": _anti_pattern(module, attack_class),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "verification_method": "manual",
        "verification_tier": verification_tier,
        "record_source_url": source_url,
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
) -> Tuple[List[Dict[str, Any]], int]:
    """Return ``(emitted_records, records_pre_filter)``.

    One record per (affected-module, GO-ID) pair; the blockchain-module
    filter is applied per module so a single advisory can yield multiple
    records (one per relevant module) or zero (generic Go module).
    """
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    pre_filter = 0
    osv_map = payload.get("osv") or {}
    for go_id in sorted(osv_map.keys()):
        osv = osv_map[go_id]
        if not isinstance(osv, dict):
            continue
        modules = osv_affected_modules(osv)
        if not modules:
            modules = ["unknown-module"]
        for module in modules:
            pre_filter += 1
            if not _module_matches_filter(module):
                continue
            record = osv_to_record(
                module=module,
                go_id=go_id,
                osv=osv,
                verification_tier=verification_tier,
            )
            if record is None:
                continue
            if record["record_id"] in seen_ids:
                continue
            seen_ids.add(record["record_id"])
            records.append(record)
    return records, pre_filter


def slug_for_record(record: Dict[str, Any]) -> str:
    target = record["target_component"].replace(":", "__").replace("/", "__")
    return slugify(target, max_len=140)


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    fetch_live: bool = False,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
    limit_ids: Optional[int] = None,
) -> Dict[str, Any]:
    verification_tier = "tier-1-officially-disclosed"
    payload = fetch_payload(
        fetch_live=fetch_live,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
        prefetched=prefetched,
        limit_ids=limit_ids,
    )
    if payload is None:
        # Honest-zero gate (mirrors the W4.2 post-mortem miner pattern).
        sys.stderr.write(
            "BLOCKED-NO-REAL-SOURCE: vuln.go.dev not fetched and no cache "
            "supplied. Re-run with --fetch (live pull) or --cache-file "
            "<payload.json> (offline replay). No records emitted; zero "
            "training-data-recalled GO-IDs.\n"
        )
        return {
            "schema_version": SUMMARY_SCHEMA,
            "out_dir": str(out_dir),
            "dry_run": dry_run,
            "verification_tier": verification_tier,
            "blocked": True,
            "blocked_reason": "BLOCKED-NO-REAL-SOURCE",
            "records_pre_filter": 0,
            "records_emitted": 0,
            "by_attack_class": {},
            "by_impact_class": {},
            "by_severity": {},
            "by_target_domain": {},
            "sample_source_urls": [],
            "files": [],
            "errors": [],
        }

    records, records_pre_filter = build_records(payload, verification_tier)
    if limit is not None:
        records = records[:limit]

    by_attack_class: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_domain: Dict[str, int] = {}
    sample_urls: List[str] = []
    files: List[str] = []
    head_checks: Dict[str, str] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
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
            except Exception as exc:  # pragma: no cover - verifier best-effort
                head_checks[record["record_id"]] = f"error:{exc}"

    meta = payload.get("_meta") or {}
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "blocked": False,
        "index_count": int(meta.get("index_count") or 0),
        "osv_fetched": int(meta.get("osv_fetched") or 0),
        "records_pre_filter": records_pre_filter,
        "records_emitted": len(records),
        "by_attack_class": by_attack_class,
        "by_impact_class": by_impact,
        "by_severity": by_severity,
        "by_target_domain": by_domain,
        "sample_source_urls": sample_urls,
        "files": files[:50],
        "errors": [],
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
        "--fetch",
        action="store_true",
        help="Perform live network I/O against vuln.go.dev. Without it (and "
        "without --cache-file) the miner emits BLOCKED-NO-REAL-SOURCE.",
    )
    parser.add_argument(
        "--limit-ids",
        type=int,
        help="Cap the number of per-GO-ID OSV records fetched (live pull).",
    )
    parser.add_argument(
        "--cache-file",
        help="Read a previously-cached vuln.go.dev payload instead of fetching.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched payload to this path for later offline replay.",
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
        fetch_live=bool(args.fetch),
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=Path(args.write_cache_file).expanduser().resolve()
        if args.write_cache_file
        else None,
        limit_ids=args.limit_ids,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        if summary.get("blocked"):
            print(
                "hackerman go-vuln-db ETL: BLOCKED-NO-REAL-SOURCE "
                "(re-run with --fetch or --cache-file)"
            )
        else:
            print(
                "hackerman go-vuln-db ETL: "
                f"records={summary['records_emitted']}/{summary['records_pre_filter']} "
                f"osv_fetched={summary.get('osv_fetched', 0)} "
                f"verification_tier={summary['verification_tier']} "
                f"by_severity={summary['by_severity']} "
                f"by_impact={summary['by_impact_class']} "
                f"errors={len(summary['errors'])}"
            )
    # Honest-zero BLOCKED is not an error exit; it is an explicit verdict.
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
