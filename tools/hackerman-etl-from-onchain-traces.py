#!/usr/bin/env python3
"""Wave-5 L3 Hackerman ETL: on-chain exploit transaction traces.

Roadmap anchor: ``docs/next_capability_plan/03_corpus_expansion.md`` lane
L3 ("On-chain exploit traces", subtree ``onchain_exploit_traces``) and
``docs/WAVE5_CAPABILITY_ROADMAP_2026-05-16.md`` row W5-G7.

Real exploit call traces are the highest-signal corpus data: they show
the actual attack path - the concrete sequence of contract calls the
attacker made - not a prose summary. This miner turns a verified exploit
transaction hash into a corpus record carrying the decoded call-path
structure (the per-depth call tree: target -> sub-call -> sub-call ...).

Seed discipline (per the L3 roadmap note, verbatim):

    "do NOT recall trace lists from training data. Seed strictly from tx
    hashes already present in post_mortem / bridge_incidents records,
    then fetch each trace from a resolvable explorer endpoint. If the
    explorer API is unreachable, the lane ships an honest-zero verdict
    rather than fabricated traces."

So the seed tx-hash set is built ONLY from one of:

* ``--tx-hashes <file>``  - newline-separated ``0x``-prefixed 32-byte tx
  hashes (one per line; blank + ``#`` lines ignored). Each line may
  optionally carry ``<txhash> <chain>`` (chain defaults to ``ethereum``).
* ``--seed-corpus <dir>`` - scan an existing corpus subtree (typically
  ``audit/corpus_tags/tags/post_mortem`` or
  ``audit/corpus_tags/tags/bridge_incidents``) for ``0x``-prefixed
  32-byte hex tx hashes embedded in the record JSON/YAML bodies.
* ``--tx <hash>`` (repeatable) - a single explicit on-chain tx hash on
  the command line, optionally ``<hash>:<chain>``.

There are NO training-data-recalled tx hashes in this file.

Trace source: a decoded-call-trace endpoint that returns a nested JSON
call tree, addressed as ``<api-base>/<chain>/<txhash>``. This miner
flattens that tree into an ordered call-path list
``[{depth, from, to, function, value, error}, ...]``. The canonical
per-tx trace URL is recorded in ``record_source_url`` so each record's
claim is independently verifiable from the URL alone.

IMPORTANT - no baked-in public trace endpoint. As of the W5-L3 build
date there is NO key-free public decoded-trace JSON API: the OpenChain
explorer (``api.openchain.xyz``) exposes only the signature database,
not traces, and Phalcon / BlockSec / Tenderly trace endpoints are
either key-gated or HTML-only. The ``DEFAULT_API_BASE`` below is a
documented placeholder; a live run MUST supply ``--api-base`` pointing
at a trace endpoint the operator has access to (a Phalcon/Tenderly API
URL with the operator's own credentials baked into the base, a
self-hosted ``debug_traceTransaction`` proxy, etc.) returning the
nested-call JSON shape. Without a reachable endpoint the lane ships an
honest-zero ``BLOCKED-NO-REAL-SOURCE`` verdict (per the L3 roadmap:
"If the explorer API is unreachable, the lane ships an honest-zero
verdict rather than fabricated traces."). ``--cache-file`` replays a
payload captured from such an endpoint offline.

Honest-zero gate (mirrors the W4.2 post-mortem and W5-L1 go-vuln-db
miners): the import / dry-run path performs ZERO network I/O. Network I/O
requires ``--fetch``. With neither ``--fetch`` nor a populated
``--cache-file`` / injected bytes, the miner prints
``BLOCKED-NO-REAL-SOURCE`` to stderr and emits zero records. No
fabricated traces, ever.

verification_tier: ``tier-2-verified-public-archive`` (per the L3
roadmap row in ``docs/next_capability_plan/03_corpus_expansion.md`` and
``docs/WAVE5_CAPABILITY_ROADMAP_2026-05-16.md`` W5-G7). A decoded
exploit trace is parsed from a public archive endpoint and the emit step
extracts the mandatory shape fields (real tx hash, decoded call
sequence, resolvable trace URL) - that is the tier-2 contract. It is
deliberately NOT tier-1: per Rule 37 ``tier-1-verified-realtime-api``
requires a live external-ID verifier call against an authoritative
advisory API (NVD/GHSA-class), which a raw trace endpoint is not. The
tier is a first-class field set at emit time on every record (Rule 37).
The miner refuses to emit any record whose tx hash is not a
syntactically valid 32-byte hash or whose trace payload has zero call
frames.

CLI:

    # Honest-zero (no network, no cache) -> BLOCKED-NO-REAL-SOURCE:
    python3 tools/hackerman-etl-from-onchain-traces.py \\
        --out-dir audit/corpus_tags/tags/onchain_exploit_traces \\
        --tx-hashes /tmp/exploit-txs.txt --dry-run

    # Live pull from explicit tx hashes:
    python3 tools/hackerman-etl-from-onchain-traces.py \\
        --out-dir audit/corpus_tags/tags/onchain_exploit_traces \\
        --tx 0xabc...:ethereum --fetch --apply

    # Live pull seeded from the post-mortem corpus:
    python3 tools/hackerman-etl-from-onchain-traces.py \\
        --out-dir audit/corpus_tags/tags/onchain_exploit_traces \\
        --seed-corpus audit/corpus_tags/tags/post_mortem --fetch --apply

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-onchain-traces.py \\
        --out-dir audit/corpus_tags/tags/onchain_exploit_traces \\
        --tx-hashes /tmp/exploit-txs.txt \\
        --cache-file /tmp/onchain-trace-cache.json --apply

Shape anchors: ``tools/hackerman-etl-from-go-vuln-db.py`` (honest-zero
gate, tier field, summary schema) and
``tools/hackerman-etl-from-post-mortem.py`` (corpus-seed scan).
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


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.2"  # lane227: incident-mining shape (onchain exploit traces with source_url/amount_usd) -> v1.2 permissive wide-shape
SUMMARY_SCHEMA = "auditooor.hackerman_etl.onchain_exploit_traces.summary.v1"

# Canonical corpus subtree for emitted records (per the L3 roadmap row,
# subtree ``onchain_exploit_traces``). Also the registry-build tool's
# Pattern-A introspection anchor.
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "onchain_exploit_traces"

# Rule 37: this miner emits at tier-2-verified-public-archive. A decoded
# call trace is parsed from a public archive endpoint and the emit step
# extracts >=3 mandatory shape fields (tx hash, call sequence, URL).
VERIFICATION_TIER = "tier-2-verified-public-archive"

# Placeholder trace-API base. There is NO key-free public decoded-trace
# JSON endpoint as of the W5-L3 build; a live run MUST override this via
# --api-base with an endpoint the operator can actually reach. Left
# non-empty only so --cache-file replay and the honest-zero gate stay
# exercisable; a live --fetch against this default will simply 404 and
# the lane ships BLOCKED-NO-REAL-SOURCE.
DEFAULT_API_BASE = "https://api.openchain.xyz/trace/v1"

# A 32-byte transaction hash: 0x followed by exactly 64 hex chars.
TX_HASH_RE = re.compile(r"\b0x[0-9a-fA-F]{64}\b")

SUPPORTED_CHAINS: Tuple[str, ...] = (
    "ethereum", "arbitrum", "optimism", "base", "polygon",
    "bsc", "avalanche", "fantom", "gnosis",
)


# ---------------------------------------------------------------------------
# Attack-class keyword table (call-path / error-text derived).
#
# A decoded trace exposes the function names actually invoked and any
# revert strings; we derive a conservative attack_class from that.
# Unmatched traces fall back to a generic on-chain-exploit class.
# ---------------------------------------------------------------------------

_CALLPATH_SYMPTOM_TABLE: Tuple[Tuple[str, str, str], ...] = (
    # keyword (lowercased; matched against function names + error text),
    # attack_class, impact_class
    ("flashloan", "flash-loan", "theft"),
    ("flash loan", "flash-loan", "theft"),
    ("flashswap", "flash-loan", "theft"),
    ("donatetoreserves", "reentrancy", "theft"),
    ("reentr", "reentrancy", "theft"),
    ("delegatecall", "delegatecall-injection", "theft"),
    ("oracle", "oracle-manipulation", "theft"),
    ("getprice", "oracle-manipulation", "theft"),
    ("latestanswer", "oracle-manipulation", "theft"),
    ("swap", "price-manipulation", "theft"),
    ("skim", "price-manipulation", "theft"),
    ("sync", "price-manipulation", "theft"),
    ("initialize", "uninitialized-proxy", "theft"),
    ("upgradeto", "uninitialized-proxy", "theft"),
    ("ecrecover", "signature-verification-bypass", "theft"),
    ("permit", "signature-replay", "theft"),
    ("processmessage", "bridge-message-replay", "theft"),
    ("proveandexecute", "bridge-message-replay", "theft"),
    ("mint", "unauthorized-mint", "theft"),
    ("burn", "accounting-error", "theft"),
    ("transferfrom", "approval-abuse", "theft"),
    ("withdraw", "theft-of-funds", "theft"),
    ("redeem", "theft-of-funds", "theft"),
    ("liquidate", "liquidation-abuse", "theft"),
)


def classify_call_path(call_path: List[Dict[str, Any]]) -> Tuple[str, str]:
    """Return ``(attack_class, impact_class)`` from a flattened call path."""
    blob_parts: List[str] = []
    for frame in call_path:
        blob_parts.append(str(frame.get("function") or ""))
        blob_parts.append(str(frame.get("error") or ""))
    blob = " ".join(blob_parts).lower()
    for kw, ac, ic in _CALLPATH_SYMPTOM_TABLE:
        if kw in blob:
            return ac, ic
    return "onchain-exploit", "theft"


# ---------------------------------------------------------------------------
# Slug / YAML helpers (shape-matched to the go-vuln-db miner)
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
# Seed tx-hash resolution (corpus-only / explicit-CLI; no training recall)
# ---------------------------------------------------------------------------


def normalize_tx_hash(raw: str) -> Optional[str]:
    """Return the lowercased ``0x``-prefixed 32-byte hash, or ``None``."""
    candidate = str(raw or "").strip().lower()
    if TX_HASH_RE.fullmatch(candidate):
        return candidate
    return None


def parse_tx_arg(raw: str) -> Optional[Tuple[str, str]]:
    """Parse a ``--tx`` value: ``<hash>`` or ``<hash>:<chain>``."""
    token = str(raw or "").strip()
    if not token:
        return None
    chain = "ethereum"
    if ":" in token and not token.startswith("0x:"):
        head, _, tail = token.partition(":")
        if normalize_tx_hash(head) is not None:
            token = head
            if tail.strip().lower() in SUPPORTED_CHAINS:
                chain = tail.strip().lower()
    tx = normalize_tx_hash(token)
    if tx is None:
        return None
    return (tx, chain)


def load_tx_hashes(path: Path) -> List[Tuple[str, str]]:
    """Parse a ``--tx-hashes`` file into ``[(txhash, chain), ...]``.

    Each non-blank, non-``#`` line is ``<txhash>`` or ``<txhash> <chain>``.
    Invalid hashes are skipped silently (the summary reports the count).
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        tx = normalize_tx_hash(parts[0])
        if tx is None:
            continue
        chain = parts[1].strip().lower() if len(parts) > 1 else "ethereum"
        if chain not in SUPPORTED_CHAINS:
            chain = "ethereum"
        key = (tx, chain)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def scan_seed_corpus(corpus_dir: Path) -> List[Tuple[str, str]]:
    """Scan an existing corpus subtree for embedded exploit tx hashes.

    Recursively reads every ``.json`` / ``.yaml`` file under ``corpus_dir``
    and extracts ``0x``-prefixed 32-byte hex strings. Chain defaults to
    ``ethereum`` (corpus records do not carry a structured chain field).
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()
    if not corpus_dir.exists():
        return out
    for path in sorted(corpus_dir.rglob("*")):
        if path.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in TX_HASH_RE.finditer(body):
            tx = m.group(0).lower()
            key = (tx, "ethereum")
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


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


def trace_url(api_base: str, chain: str, tx_hash: str) -> str:
    return f"{api_base.rstrip('/')}/{chain}/{tx_hash}"


def fetch_payload(
    *,
    seeds: List[Tuple[str, str]],
    api_base: str,
    fetch_live: bool,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
) -> Optional[Dict[str, Any]]:
    """Build ``{"_meta": {...}, "traces": {trace_url: <raw json>}}``.

    Returns ``None`` when no real source is available (honest-zero gate):
    no cache file, no injected prefetched bytes, and ``--fetch`` not set.
    """
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))

    prefetched = dict(prefetched or {})

    # Honest-zero gate: zero network and zero injected bytes -> BLOCKED.
    if not fetch_live and not prefetched:
        return None

    traces: Dict[str, Any] = {}
    errors: List[str] = []
    for tx_hash, chain in seeds:
        url = trace_url(api_base, chain, tx_hash)
        if url in prefetched:
            raw = prefetched[url]
        elif fetch_live:
            raw = _curl_get(url)
        else:
            raw = None
        if raw is None:
            errors.append(f"unresolved trace {chain}:{tx_hash}")
            continue
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            errors.append(f"unparseable trace {chain}:{tx_hash}")
            continue
        traces[url] = parsed

    payload: Dict[str, Any] = {
        "_meta": {
            "seeds_count": len(seeds),
            "traces_fetched": len(traces),
            "fetch_errors": errors,
            "api_base": api_base,
        },
        "traces": traces,
    }
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
    return payload


# ---------------------------------------------------------------------------
# Trace-JSON flattening
#
# The OpenChain trace endpoint returns a nested call tree. The exact key
# layout varies slightly across mirrors, so the flattener probes a small
# set of well-known key aliases. The result is a depth-ordered list of
# call frames.
# ---------------------------------------------------------------------------

_CHILDREN_KEYS = ("calls", "children", "subcalls", "subtraces")
_FROM_KEYS = ("from", "caller", "sender")
_TO_KEYS = ("to", "target", "address", "contract")
_FUNC_KEYS = ("function", "functionName", "method", "name", "signature")
_VALUE_KEYS = ("value", "callValue", "amount")
_ERROR_KEYS = ("error", "revert", "revertReason", "errorMessage")
_TYPE_KEYS = ("type", "callType", "kind")


def _first_key(node: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    for k in keys:
        if k in node and node[k] not in (None, ""):
            return node[k]
    return None


def _trace_root(parsed: Any) -> Optional[Dict[str, Any]]:
    """Return the root call node from a trace payload (probes wrappers)."""
    if isinstance(parsed, dict):
        # Some endpoints wrap the tree: {"result": {...}} / {"trace": {...}}.
        for wrapper in ("result", "trace", "data", "callTrace", "root"):
            inner = parsed.get(wrapper)
            if isinstance(inner, dict):
                return inner
            if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                return {"calls": inner}
        return parsed
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return {"calls": parsed}
    return None


def flatten_call_path(parsed: Any, *, max_frames: int = 400) -> List[Dict[str, Any]]:
    """Flatten a nested trace tree into a depth-ordered call-path list."""
    root = _trace_root(parsed)
    if root is None:
        return []
    out: List[Dict[str, Any]] = []

    def walk(node: Dict[str, Any], depth: int) -> None:
        if len(out) >= max_frames:
            return
        frame = {
            "depth": depth,
            "call_type": one_line(_first_key(node, _TYPE_KEYS), "CALL", max_len=24),
            "from": one_line(_first_key(node, _FROM_KEYS), "", max_len=64),
            "to": one_line(_first_key(node, _TO_KEYS), "", max_len=64),
            "function": one_line(_first_key(node, _FUNC_KEYS), "", max_len=200),
            "value": one_line(_first_key(node, _VALUE_KEYS), "0", max_len=80),
            "error": one_line(_first_key(node, _ERROR_KEYS), "", max_len=300),
        }
        # Only record nodes that carry at least a `to` or a `function`.
        if frame["to"] or frame["function"]:
            out.append(frame)
        children = _first_key(node, _CHILDREN_KEYS)
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    walk(child, depth + 1)

    walk(root, 0)
    return out


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _record_id(tx_hash: str, chain: str) -> str:
    digest = hashlib.sha256(f"onchain-trace|{chain}|{tx_hash}".encode("utf-8")).hexdigest()[:12]
    return f"onchain-trace:{chain}:{tx_hash[:14]}:{digest}"[:160]


def _function_shape(
    tx_hash: str,
    chain: str,
    attack_class: str,
    call_path: List[Dict[str, Any]],
) -> Dict[str, Any]:
    shape_tags: List[str] = [
        "onchain-exploit-trace",
        slugify(f"chain-{chain}", max_len=40),
        slugify(attack_class, max_len=64),
        slugify(f"call-depth-{max((f['depth'] for f in call_path), default=0)}", max_len=40),
    ]
    # The entry function is the most diagnostic single tag.
    entry_fn = ""
    for f in call_path:
        if f.get("function"):
            entry_fn = f["function"]
            break
    if entry_fn:
        shape_tags.append(slugify(f"entry-{entry_fn}", max_len=80))
    seen: set = set()
    uniq: List[str] = []
    for t in shape_tags:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    raw_sig = " -> ".join(
        f["function"] or f["to"] or "?" for f in call_path[:12]
    )
    return {"raw_signature": raw_sig[:500] or "onchain-exploit-trace", "shape_tags": uniq}


def _attacker_action_sequence(
    tx_hash: str,
    chain: str,
    call_path: List[Dict[str, Any]],
    attack_class: str,
    verification_tier: str,
) -> str:
    steps: List[str] = []
    for f in call_path[:24]:
        label = f["function"] or f["to"] or "?"
        steps.append(f"d{f['depth']}:{label}")
    body = "Attacker call path: " + " | ".join(steps)
    marker = (
        f" [tx={tx_hash}; chain={chain}; attack_class={attack_class}; "
        f"verification_tier={verification_tier}]"
    )
    body_max = 4900 - len(marker)
    return (one_line(body, "on-chain exploit trace", max_len=body_max) + marker).strip()


def trace_to_record(
    *,
    tx_hash: str,
    chain: str,
    trace_url_str: str,
    parsed: Any,
    verification_tier: str = VERIFICATION_TIER,
) -> Optional[Dict[str, Any]]:
    """Build one schema-v1.1 hackerman record from one decoded trace.

    Returns ``None`` for an invalid tx hash or an empty call path (no
    fabricated traces).
    """
    if normalize_tx_hash(tx_hash) is None:
        return None
    call_path = flatten_call_path(parsed)
    if not call_path:
        return None
    attack_class, impact_class = classify_call_path(call_path)
    target_component = call_path[0].get("to") or "unknown-contract"
    max_depth = max((f["depth"] for f in call_path), default=0)
    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _record_id(tx_hash, chain),
        "source_audit_ref": one_line(trace_url_str, f"onchain-trace:{tx_hash}", max_len=240),
        "target_domain": "smart-contract",
        "target_language": "solidity",
        "target_repo": f"onchain:{chain}",
        "target_component": one_line(target_component, "unknown-contract", max_len=240),
        "function_shape": _function_shape(tx_hash, chain, attack_class, call_path),
        "bug_class": "onchain-exploit-trace",
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(
            tx_hash, chain, call_path, attack_class, verification_tier
        ),
        "required_preconditions": [
            f"On-chain exploit transaction {tx_hash} on chain {chain}",
            f"Decoded call trace resolvable at {trace_url_str}",
            f"Call path depth {max_depth} with {len(call_path)} call frames",
            f"verification_tier={verification_tier}",
        ],
        "impact_class": impact_class,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "unspecified",
        "fix_pattern": (
            "Audit every call frame on this attack path; the exploit "
            "primitive is the externally-reachable entry call that no "
            "downstream guard rejects. Add the missing check at the entry "
            "frame, not deeper in the path."
        ),
        "fix_anti_pattern_avoided": (
            "Assuming a deep internal call is unreachable because the "
            "entry function looks benign; the trace proves the full path "
            "was traversed in a single transaction."
        ),
        "severity_at_finding": "high",
        "year": _year_from_tx_meta(parsed),
        "record_tier": "public-corpus",
        "record_quality_score": 4.5,
        "source_extraction_method": "onchain-trace-api",
        "source_extraction_confidence": 0.95,
        "verification_method": "onchain-trace",
        "verification_tier": verification_tier,
        "record_source_url": trace_url_str,
        "cross_language_analogues": [],
        "related_records": [],
        "record_extensions": {
            "tx_hash": tx_hash,
            "chain": chain,
            "call_path": call_path,
            "call_frame_count": len(call_path),
            "max_call_depth": max_depth,
        },
    }
    return record


def _year_from_tx_meta(parsed: Any) -> int:
    """Best-effort year extraction from any timestamp in the trace payload."""
    if isinstance(parsed, dict):
        for key in ("timestamp", "blockTimestamp", "time", "date"):
            val = parsed.get(key)
            if isinstance(val, str) and len(val) >= 4 and val[:4].isdigit():
                y = int(val[:4])
                if 2000 <= y <= 2100:
                    return y
    return 2024


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_records(
    payload: Dict[str, Any],
    verification_tier: str = VERIFICATION_TIER,
) -> List[Dict[str, Any]]:
    """Return one record per resolvable trace in the payload."""
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    traces = payload.get("traces") or {}
    for url in sorted(traces.keys()):
        # url shape: <api_base>/<chain>/<txhash>
        m = re.search(r"/([a-z0-9-]+)/(0x[0-9a-fA-F]{64})$", url)
        if not m:
            continue
        chain, tx_hash = m.group(1), m.group(2).lower()
        record = trace_to_record(
            tx_hash=tx_hash,
            chain=chain,
            trace_url_str=url,
            parsed=traces[url],
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
    ext = record.get("record_extensions") or {}
    basis = f"{ext.get('chain', 'ethereum')}-{ext.get('tx_hash', '')[:14]}"
    return slugify(basis, max_len=140)


def convert(
    out_dir: Path,
    *,
    seeds: List[Tuple[str, str]],
    api_base: str = DEFAULT_API_BASE,
    dry_run: bool = False,
    limit: Optional[int] = None,
    fetch_live: bool = False,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    prefetched: Optional[Dict[str, bytes]] = None,
) -> Dict[str, Any]:
    verification_tier = VERIFICATION_TIER

    if not seeds and cache_file is None:
        sys.stderr.write(
            "BLOCKED-NO-REAL-SOURCE: no seed tx hashes. Supply --tx <hash>, "
            "--tx-hashes <file>, or --seed-corpus <dir> (no training-data-"
            "recalled hashes in this miner).\n"
        )
        return _blocked_summary(out_dir, dry_run, verification_tier,
                                "BLOCKED-NO-REAL-SOURCE-NO-SEEDS")

    payload = fetch_payload(
        seeds=seeds,
        api_base=api_base,
        fetch_live=fetch_live,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
        prefetched=prefetched,
    )
    if payload is None:
        # Honest-zero gate.
        sys.stderr.write(
            "BLOCKED-NO-REAL-SOURCE: trace API not fetched and no cache "
            "supplied. Re-run with --fetch + --api-base <reachable trace "
            "endpoint>, or --cache-file <payload.json> (offline replay). "
            "No records emitted; no fabricated traces.\n"
        )
        return _blocked_summary(out_dir, dry_run, verification_tier,
                                "BLOCKED-NO-REAL-SOURCE")

    records = build_records(payload, verification_tier)
    if limit is not None:
        records = records[:limit]

    by_attack_class: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}
    by_chain: Dict[str, int] = {}
    sample_urls: List[str] = []
    files: List[str] = []

    if not dry_run and records:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        by_impact[record["impact_class"]] = by_impact.get(record["impact_class"], 0) + 1
        ch = (record.get("record_extensions") or {}).get("chain", "ethereum")
        by_chain[ch] = by_chain.get(ch, 0) + 1
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
                json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            yaml_path.write_text(yaml_dump(record), encoding="utf-8")

    meta = payload.get("_meta") or {}
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "blocked": False,
        "seeds_count": int(meta.get("seeds_count") or len(seeds)),
        "traces_fetched": int(meta.get("traces_fetched") or 0),
        "records_emitted": len(records),
        "by_attack_class": by_attack_class,
        "by_impact_class": by_impact,
        "by_chain": by_chain,
        "sample_source_urls": sample_urls,
        "files": files[:50],
        "errors": list(meta.get("fetch_errors") or []),
    }


def _blocked_summary(
    out_dir: Path, dry_run: bool, verification_tier: str, reason: str
) -> Dict[str, Any]:
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "blocked": True,
        "blocked_reason": reason,
        "seeds_count": 0,
        "traces_fetched": 0,
        "records_emitted": 0,
        "by_attack_class": {},
        "by_impact_class": {},
        "by_chain": {},
        "sample_source_urls": [],
        "files": [],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help=f"Record output subtree (default {DEFAULT_OUT_DIR}).",
    )
    parser.add_argument(
        "--tx",
        action="append",
        default=[],
        help="A single 0x-prefixed 32-byte exploit tx hash (optionally "
        "'<hash>:<chain>'). Repeatable. Only real on-chain hashes.",
    )
    parser.add_argument(
        "--tx-hashes",
        help="Newline-separated file of 0x-prefixed 32-byte tx hashes "
        "(optionally '<txhash> <chain>' per line).",
    )
    parser.add_argument(
        "--seed-corpus",
        help="Scan an existing corpus subtree (e.g. "
        "audit/corpus_tags/tags/post_mortem) for embedded exploit tx hashes.",
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help=f"Trace API base URL (default {DEFAULT_API_BASE}).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Write records (default behaviour is dry-run).")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Perform live network I/O against the trace API. Without it "
        "(and without --cache-file) the miner emits BLOCKED-NO-REAL-SOURCE.",
    )
    parser.add_argument(
        "--cache-file",
        help="Read a previously-cached trace payload instead of fetching.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched payload to this path for offline replay.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    # dry-run unless --apply is given (mirrors the Makefile APPLY knob).
    dry_run = not bool(args.apply)
    if args.dry_run:
        dry_run = True

    seeds: List[Tuple[str, str]] = []
    for raw in args.tx:
        parsed_tx = parse_tx_arg(raw)
        if parsed_tx is None:
            print(f"--tx ignored (not a 32-byte 0x hash): {raw}", file=sys.stderr)
            continue
        seeds.append(parsed_tx)
    if args.tx_hashes:
        tx_path = Path(args.tx_hashes).expanduser().resolve()
        if not tx_path.exists():
            print(f"--tx-hashes path missing: {tx_path}", file=sys.stderr)
            return 2
        seeds.extend(load_tx_hashes(tx_path))
    if args.seed_corpus:
        corpus_path = Path(args.seed_corpus).expanduser().resolve()
        seeds.extend(scan_seed_corpus(corpus_path))
    # Dedup across the seed sources.
    seen: set = set()
    deduped: List[Tuple[str, str]] = []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    seeds = deduped

    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        seeds=seeds,
        api_base=args.api_base,
        dry_run=dry_run,
        limit=args.limit,
        fetch_live=bool(args.fetch),
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file else None,
        write_cache_file=Path(args.write_cache_file).expanduser().resolve()
        if args.write_cache_file else None,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        if summary.get("blocked"):
            print(
                "hackerman onchain-traces ETL: "
                f"{summary.get('blocked_reason', 'BLOCKED-NO-REAL-SOURCE')} "
                "(re-run with seeds + --fetch or --cache-file)"
            )
        else:
            print(
                "hackerman onchain-traces ETL: "
                f"records={summary['records_emitted']} "
                f"seeds={summary['seeds_count']} "
                f"traces_fetched={summary['traces_fetched']} "
                f"verification_tier={summary['verification_tier']} "
                f"by_attack_class={summary['by_attack_class']} "
                f"by_chain={summary['by_chain']} "
                f"errors={len(summary['errors'])}"
            )
    # Honest-zero BLOCKED is an explicit verdict, not an error exit.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
