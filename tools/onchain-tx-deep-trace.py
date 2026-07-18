#!/usr/bin/env python3
# r36-rebuttal: lane-LIFT-7-ONCHAIN-TX-DEEP-MINING declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start
"""LIFT-7 on-chain TX deep trace miner.

Walks the highest-impact incident corpus records (sorted by ``amount_usd``
DESC), fetches per-tx deep traces from the chain's block explorer, and
appends an ``onchain_trace_extraction`` block to each record.yaml.

Roadmap anchor: ``/tmp/spawn_worker_LIFT-7-ONCHAIN-TX-DEEP-MINING_*_enriched.md``
under the LIFT-7 lane spawn.

Discipline (L33 dual-export, R37 verification-tier, R36 pathspec,
L34 corpus enrichment is workspace-ledger / auto-executable):

* API keys are read STRICTLY from shell env (per L33). If a chain's key
  is missing, that chain's records are skipped and added to the cursor's
  ``blocked_no_api_key`` list. No baked-in keys; no fabricated traces.
* Free-tier rate limit (~5 req/s typical) is enforced via a token-bucket
  throttle per explorer host.
* Each fetched field carries an ``evidence_url`` pointing back at the
  explorer page so any operator can independently verify the claim (L26).
* The record's ``verification_tier`` is PRESERVED, never rewritten (R37).
* Re-runs resume from a cursor at
  ``.auditooor/external_intel_cursors/onchain_tx_trace.json`` so already
  processed tx hashes are not re-fetched.
* Operator-imposed ceiling: ``--top-n`` defaults to 100. Records with
  ``amount_usd is None`` or empty ``tx_hashes`` are skipped before
  ranking. Honest-zero exit when no chain has a usable API key.

Supported chains and env-var fallbacks::

    ethereum   -> ETHERSCAN_API_KEY            (api.etherscan.io)
    bsc        -> BSCSCAN_API_KEY              (api.bscscan.com)
    polygon    -> POLYGONSCAN_API_KEY          (api.polygonscan.com)
    arbitrum   -> ARBISCAN_API_KEY             (api.arbiscan.io)
    base       -> BASESCAN_API_KEY             (api.basescan.org)
    optimism   -> OPTIMISTIC_ETHERSCAN_API_KEY (api-optimistic.etherscan.io)
    avalanche  -> SNOWTRACE_API_KEY            (api.snowtrace.io)
    fantom     -> FTMSCAN_API_KEY              (api.ftmscan.com)
    linea      -> LINEASCAN_API_KEY            (api.lineascan.build)
    tron       -> TRONSCAN_API_KEY (optional)  (apilist.tronscanapi.com)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import yaml

# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py register --lane lane-LIFT-7-RERUN-WITH-KEY --files tools/onchain-tx-deep-trace.py,... (TTL 5400s, lane title "LIFT-7 RE-RUN with ETHERSCAN_API_KEY (V2 unified endpoint + rate-limit/daily-cap CLI extension)")
SCHEMA_VERSION = "auditooor.onchain_tx_deep_trace.v1"

# Etherscan V2 unified Multi-Chain API endpoint (single key covers all
# etherscan-family chains).  Per-chain dispatch is driven by ``chainid``.
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"

CHAIN_CONFIG: dict[str, dict[str, Any]] = {
    "ethereum": {
        "api_base": "https://api.etherscan.io/api",
        "web_base": "https://etherscan.io/tx/",
        "env_key": "ETHERSCAN_API_KEY",
        "chain_id": 1,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "bsc": {
        "api_base": "https://api.bscscan.com/api",
        "web_base": "https://bscscan.com/tx/",
        "env_key": "BSCSCAN_API_KEY",
        "chain_id": 56,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "polygon": {
        "api_base": "https://api.polygonscan.com/api",
        "web_base": "https://polygonscan.com/tx/",
        "env_key": "POLYGONSCAN_API_KEY",
        "chain_id": 137,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "arbitrum": {
        "api_base": "https://api.arbiscan.io/api",
        "web_base": "https://arbiscan.io/tx/",
        "env_key": "ARBISCAN_API_KEY",
        "chain_id": 42161,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "base": {
        "api_base": "https://api.basescan.org/api",
        "web_base": "https://basescan.org/tx/",
        "env_key": "BASESCAN_API_KEY",
        "chain_id": 8453,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "optimism": {
        "api_base": "https://api-optimistic.etherscan.io/api",
        "web_base": "https://optimistic.etherscan.io/tx/",
        "env_key": "OPTIMISTIC_ETHERSCAN_API_KEY",
        "chain_id": 10,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "avalanche": {
        "api_base": "https://api.snowtrace.io/api",
        "web_base": "https://snowtrace.io/tx/",
        "env_key": "SNOWTRACE_API_KEY",
        "chain_id": 43114,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "fantom": {
        "api_base": "https://api.ftmscan.com/api",
        "web_base": "https://ftmscan.com/tx/",
        "env_key": "FTMSCAN_API_KEY",
        "chain_id": 250,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "linea": {
        "api_base": "https://api.lineascan.build/api",
        "web_base": "https://lineascan.build/tx/",
        "env_key": "LINEASCAN_API_KEY",
        "chain_id": 59144,
        "throttle_qps": 5.0,
        "family": "etherscan",
    },
    "tron": {
        "api_base": "https://apilist.tronscanapi.com/api",
        "web_base": "https://tronscan.org/#/transaction/",
        "env_key": "TRONSCAN_API_KEY",
        "chain_id": None,
        "throttle_qps": 5.0,
        "family": "tron",
    },
}

FOURBYTE_BASE = "https://www.4byte.directory/api/v1/signatures/?hex_signature="


def load_cursor(cursor_path: Path) -> dict[str, Any]:
    """Return cursor dict, or a fresh skeleton when missing/unreadable."""
    if not cursor_path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "processed_tx_hashes": [],
            "blocked_no_api_key": [],
            "rate_limit_pauses": [],
            "fetch_errors": [],
            "last_run_utc": None,
        }
    try:
        return json.loads(cursor_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {
            "schema_version": SCHEMA_VERSION,
            "processed_tx_hashes": [],
            "blocked_no_api_key": [],
            "rate_limit_pauses": [],
            "fetch_errors": [],
            "last_run_utc": None,
        }


def save_cursor(cursor_path: Path, cursor: dict[str, Any]) -> None:
    cursor_path.parent.mkdir(parents=True, exist_ok=True)
    cursor["last_run_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cursor_path.write_text(json.dumps(cursor, indent=2, sort_keys=True) + "\n")


def discover_corpus_records(corpus_dirs: list[Path]) -> list[Path]:
    """Return every ``record.yaml`` under each corpus dir (recursive)."""
    out: list[Path] = []
    for d in corpus_dirs:
        if not d.exists():
            continue
        out.extend(sorted(d.rglob("record.yaml")))
    return out


def load_record(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None


def get_chain_value(record: dict[str, Any]) -> str | None:
    """Pull the chain hint out of structured_extraction.chain."""
    se = record.get("structured_extraction") or {}
    chain_v = se.get("chain")
    if isinstance(chain_v, dict):
        v = chain_v.get("value")
        return v.lower() if isinstance(v, str) and v else None
    if isinstance(chain_v, str) and chain_v:
        return chain_v.lower()
    return None


def get_tx_hashes(record: dict[str, Any]) -> list[str]:
    se = record.get("structured_extraction") or {}
    txs = se.get("tx_hashes") or []
    if not isinstance(txs, list):
        return []
    out = []
    for tx in txs:
        if isinstance(tx, str) and tx.startswith("0x") and len(tx) == 66:
            out.append(tx.lower())
        elif isinstance(tx, dict):
            v = tx.get("hash") or tx.get("tx_hash")
            if isinstance(v, str) and v.startswith("0x") and len(v) == 66:
                out.append(v.lower())
    return out


def rank_candidates(
    records: list[tuple[Path, dict[str, Any]]],
    top_n: int,
    sort_by: str,
) -> list[tuple[Path, dict[str, Any]]]:
    """Filter to records with non-empty tx_hashes + non-null amount_usd, sort, slice top-N."""
    eligible: list[tuple[Any, Path, dict[str, Any]]] = []
    for path, rec in records:
        if not rec:
            continue
        amt = rec.get("amount_usd")
        if amt is None:
            continue
        if not get_tx_hashes(rec):
            continue
        if sort_by == "amount_usd":
            try:
                key = float(amt)
            except (TypeError, ValueError):
                continue
        else:
            key = 0.0
        eligible.append((key, path, rec))
    eligible.sort(key=lambda r: -r[0])
    return [(p, r) for _, p, r in eligible[: max(top_n, 0)]]


# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
class HostThrottle:
    """Per-host token bucket. ``acquire`` blocks until a slot is free.

    Optional ``global_qps`` clamps the COMBINED qps across all hosts (used
    for the V2 unified endpoint where a single API key is shared across
    every chain).  Optional ``daily_cap`` enforces a per-day max-call
    ceiling; once reached, ``acquire`` returns ``-1.0`` instead of
    sleeping and the caller treats the request as ``blocked_daily_cap``.
    """

    def __init__(
        self,
        global_qps: float | None = None,
        daily_cap: int | None = None,
        daily_used: int = 0,
    ) -> None:
        self._last_call: dict[str, float] = defaultdict(lambda: 0.0)
        self._global_last: float = 0.0
        self._global_qps: float | None = global_qps
        self._daily_cap: int | None = daily_cap
        self._daily_used: int = max(0, int(daily_used))

    @property
    def daily_used(self) -> int:
        return self._daily_used

    def acquire(self, host_key: str, qps: float, sleeper=time.sleep, now=time.monotonic) -> float:
        # Daily cap check (does NOT increment; check before commit).
        if self._daily_cap is not None and self._daily_used >= self._daily_cap:
            return -1.0
        wait_total = 0.0
        # Per-host throttle.
        if qps > 0:
            min_interval = 1.0 / qps
            elapsed = now() - self._last_call[host_key]
            if elapsed < min_interval:
                wait = min_interval - elapsed
                sleeper(wait)
                wait_total += wait
        # Global throttle (combined-qps clamp).
        if self._global_qps and self._global_qps > 0:
            min_interval = 1.0 / self._global_qps
            elapsed = now() - self._global_last
            if elapsed < min_interval:
                wait = min_interval - elapsed
                sleeper(wait)
                wait_total += wait
            self._global_last = now()
        # Commit timestamps + daily counter.
        self._last_call[host_key] = now()
        self._daily_used += 1
        return wait_total


def _http_get_json(
    url: str,
    *,
    timeout: float = 10.0,
    http_fn=None,
) -> dict[str, Any] | list[Any] | None:
    if http_fn is not None:
        return http_fn(url)
    try:
        req = urllib_request.Request(url, headers={"User-Agent": "auditooor-onchain-tx-deep-trace/1"})
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            if not body:
                return None
            return json.loads(body.decode("utf-8", errors="replace"))
    except (urllib_error.URLError, urllib_error.HTTPError, json.JSONDecodeError, TimeoutError, ConnectionError):
        return None


def _hex_to_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def _normalise_etherscan_tx(
    chain: str,
    tx_hash: str,
    tx: dict[str, Any],
    receipt: dict[str, Any] | None,
    internal_txs_raw: list[dict[str, Any]],
) -> dict[str, Any]:
    input_data = tx.get("input") or ""
    selector = ""
    if isinstance(input_data, str) and len(input_data) >= 10 and input_data.startswith("0x"):
        selector = input_data[:10].lower()
    status: str
    if receipt is None:
        status = "unknown"
    else:
        st_int = _hex_to_int(receipt.get("status"))
        if st_int == 1:
            status = "success"
        elif st_int == 0:
            status = "revert"
        else:
            status = "unknown"

    internal = []
    for itx in internal_txs_raw:
        internal.append({
            "from": itx.get("from"),
            "to": itx.get("to"),
            "value_wei": itx.get("value"),
            "gas": itx.get("gas"),
            "input": itx.get("input"),
            "type": itx.get("type"),
            "is_error": itx.get("isError"),
        })

    events: list[dict[str, Any]] = []
    if receipt and isinstance(receipt.get("logs"), list):
        for log in receipt["logs"]:
            events.append({
                "address": log.get("address"),
                "topics": log.get("topics") or [],
                "data": log.get("data"),
            })

    cfg = CHAIN_CONFIG[chain]
    evidence_url = f"{cfg['web_base']}{tx_hash}"

    return {
        "tx_hash": tx_hash,
        "chain": chain,
        "fetch_status": "ok",
        "block_number": _hex_to_int(tx.get("blockNumber")),
        "block_hash": tx.get("blockHash"),
        "from_address": tx.get("from"),
        "to_address": tx.get("to"),
        "value_wei": _hex_to_int(tx.get("value")),
        "gas_used": _hex_to_int(receipt.get("gasUsed")) if receipt else None,
        "gas_price": _hex_to_int(tx.get("gasPrice")),
        "input_data": input_data,
        "function_selector": selector,
        "decoded_function_signature": None,
        "status": status,
        "internal_txs": internal,
        "emitted_events": events,
        "transaction_index": _hex_to_int(tx.get("transactionIndex")),
        "nonce": _hex_to_int(tx.get("nonce")),
        "evidence_url": evidence_url,
        "endpoint_family": "etherscan",
    }


# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
def _etherscan_endpoints(chain: str, tx_hash: str, api_key: str, use_v2: bool) -> tuple[str, str, str, str]:
    """Return (host_key, tx_url, rc_url, itx_url) honouring V2 vs legacy."""
    cfg = CHAIN_CONFIG[chain]
    if use_v2:
        cid = cfg.get("chain_id")
        host_key = "api.etherscan.io"
        base = f"{ETHERSCAN_V2_API}?chainid={cid}"
        tx_url = f"{base}&module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={api_key}"
        rc_url = f"{base}&module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={api_key}"
        itx_url = f"{base}&module=account&action=txlistinternal&txhash={tx_hash}&apikey={api_key}"
        return host_key, tx_url, rc_url, itx_url
    api_base = cfg["api_base"]
    host_key = urllib_parse.urlparse(api_base).hostname or chain
    tx_url = f"{api_base}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={api_key}"
    rc_url = f"{api_base}?module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={api_key}"
    itx_url = f"{api_base}?module=account&action=txlistinternal&txhash={tx_hash}&apikey={api_key}"
    return host_key, tx_url, rc_url, itx_url


def fetch_etherscan_tx(
    chain: str,
    tx_hash: str,
    api_key: str,
    *,
    throttle: HostThrottle | None = None,
    http_fn=None,
    use_v2: bool = False,
) -> dict[str, Any]:
    """Fetch tx + receipt + internal_txs from an Etherscan-family API.

    When ``use_v2`` is True the request is routed through the V2 unified
    Multi-Chain endpoint (``https://api.etherscan.io/v2/api?chainid=<id>``)
    so that a single ``ETHERSCAN_API_KEY`` covers every etherscan-family
    chain.  When False the per-chain hostname (legacy v1) is used.
    """
    cfg = CHAIN_CONFIG[chain]
    throttle = throttle or HostThrottle()
    qps = float(cfg.get("throttle_qps", 5.0))
    host, tx_url, rc_url, itx_url = _etherscan_endpoints(chain, tx_hash, api_key, use_v2)

    if throttle.acquire(host, qps) < 0:
        return {"fetch_status": "blocked_daily_cap", "endpoint_url": tx_url}
    tx_payload = _http_get_json(tx_url, http_fn=http_fn)
    if not isinstance(tx_payload, dict) or "result" not in tx_payload or not tx_payload["result"]:
        return {"fetch_status": "fetch_error", "endpoint_url": tx_url}
    tx = tx_payload["result"]
    # r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
    # Etherscan v1 deprecation: when the legacy endpoint is hit the API
    # responds with ``{"status":"0","message":"NOTOK","result":"<str>"}``
    # instead of an object.  Treat any non-dict ``result`` as a typed
    # API-error so the rest of the pipeline degrades gracefully.
    if not isinstance(tx, dict):
        return {
            "fetch_status": "api_error",
            "endpoint_url": tx_url,
            "api_message": tx_payload.get("message"),
            "api_result": tx if isinstance(tx, str) else str(tx),
        }

    if throttle.acquire(host, qps) < 0:
        return {"fetch_status": "blocked_daily_cap", "endpoint_url": rc_url}
    rc_payload = _http_get_json(rc_url, http_fn=http_fn)
    receipt = rc_payload.get("result") if isinstance(rc_payload, dict) else None
    if not isinstance(receipt, (dict, type(None))):
        receipt = None

    if throttle.acquire(host, qps) < 0:
        return {"fetch_status": "blocked_daily_cap", "endpoint_url": itx_url}
    itx_payload = _http_get_json(itx_url, http_fn=http_fn)
    internal_txs_raw = itx_payload.get("result") if isinstance(itx_payload, dict) else None
    if not isinstance(internal_txs_raw, list):
        internal_txs_raw = []

    return _normalise_etherscan_tx(chain, tx_hash, tx, receipt, internal_txs_raw)


def fetch_tron_tx(
    chain: str,
    tx_hash: str,
    api_key: str,
    *,
    throttle: HostThrottle | None = None,
    http_fn=None,
) -> dict[str, Any]:
    """Tron lookup via Tronscan REST. ``api_key`` may be empty."""
    cfg = CHAIN_CONFIG[chain]
    api_base = cfg["api_base"]
    host = urllib_parse.urlparse(api_base).hostname or chain
    throttle = throttle or HostThrottle()
    qps = float(cfg.get("throttle_qps", 5.0))
    throttle.acquire(host, qps)

    tx_url = f"{api_base}/transaction-info?hash={tx_hash}"
    if api_key:
        tx_url += f"&apikey={api_key}"
    payload = _http_get_json(tx_url, http_fn=http_fn)
    if not isinstance(payload, dict):
        return {"fetch_status": "fetch_error", "endpoint_url": tx_url}

    evidence_url = f"{cfg['web_base']}{tx_hash}"
    contract_data = payload.get("contractData") if isinstance(payload.get("contractData"), dict) else {}
    cost = payload.get("cost") if isinstance(payload.get("cost"), dict) else {}
    return {
        "tx_hash": tx_hash,
        "chain": chain,
        "fetch_status": "ok",
        "block_number": payload.get("block") if isinstance(payload.get("block"), int) else None,
        "block_hash": payload.get("hash"),
        "from_address": payload.get("ownerAddress"),
        "to_address": payload.get("toAddress") or payload.get("contractAddress"),
        "value_wei": contract_data.get("amount"),
        "gas_used": cost.get("net_usage"),
        "gas_price": cost.get("net_fee"),
        "input_data": payload.get("data"),
        "function_selector": "",
        "decoded_function_signature": None,
        "status": "success" if payload.get("contractRet") == "SUCCESS" else ("revert" if payload.get("contractRet") else "unknown"),
        "internal_txs": payload.get("internal_transactions") or [],
        "emitted_events": payload.get("trc20TransferInfo") or [],
        "transaction_index": None,
        "nonce": None,
        "evidence_url": evidence_url,
        "endpoint_family": "tron",
    }


def resolve_function_signature(selector: str, http_fn=None, throttle: HostThrottle | None = None) -> str | None:
    """Best-effort 4byte.directory lookup."""
    if not selector or not selector.startswith("0x") or len(selector) != 10:
        return None
    throttle = throttle or HostThrottle()
    throttle.acquire("www.4byte.directory", 5.0)
    payload = _http_get_json(FOURBYTE_BASE + selector, http_fn=http_fn)
    if not isinstance(payload, dict):
        return None
    results = payload.get("results") or []
    if not results:
        return None
    return results[0].get("text_signature")


# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
def fetch_tx(
    chain: str,
    tx_hash: str,
    api_keys: dict[str, str],
    *,
    throttle: HostThrottle | None = None,
    http_fn=None,
    resolve_selector: bool = True,
    use_v2_chains: set[str] | None = None,
) -> dict[str, Any]:
    """Per-tx fetch dispatcher. Returns trace dict or a typed error stub.

    ``use_v2_chains`` is the set of chains that should use the Etherscan
    V2 unified Multi-Chain endpoint (driven by ``chainid``) because they
    rely on the unified ``ETHERSCAN_API_KEY`` rather than a per-chain
    legacy key.  Chains absent from the set keep the per-chain hostname.
    """
    if chain not in CHAIN_CONFIG:
        return {"tx_hash": tx_hash, "chain": chain, "fetch_status": "unsupported_chain"}
    api_key = api_keys.get(chain, "")
    cfg = CHAIN_CONFIG[chain]
    if cfg["family"] == "etherscan" and not api_key:
        return {"tx_hash": tx_hash, "chain": chain, "fetch_status": "blocked_no_api_key"}
    if cfg["family"] == "etherscan":
        use_v2 = bool(use_v2_chains and chain in use_v2_chains)
        out = fetch_etherscan_tx(chain, tx_hash, api_key, throttle=throttle, http_fn=http_fn, use_v2=use_v2)
    else:
        out = fetch_tron_tx(chain, tx_hash, api_key, throttle=throttle, http_fn=http_fn)
    if out.get("fetch_status") == "ok" and resolve_selector:
        sel = out.get("function_selector") or ""
        sig = resolve_function_signature(sel, http_fn=http_fn, throttle=throttle)
        if sig:
            out["decoded_function_signature"] = sig
    return out


# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
def resolve_api_keys(
    env: dict[str, str] | None = None,
) -> tuple[dict[str, str], list[str], set[str]]:
    """Return (per-chain api_key map, blocked list, v2-key chain set).

    Resolution order per etherscan-family chain:

    1. Per-chain env (``BSCSCAN_API_KEY``, ``POLYGONSCAN_API_KEY``,
       ``ARBISCAN_API_KEY``, ``BASESCAN_API_KEY``, ...) -> legacy v1.
    2. Unified ``ETHERSCAN_API_KEY`` -> Etherscan V2 unified endpoint.

    The third tuple element enumerates the chains whose key came from the
    unified ``ETHERSCAN_API_KEY``; ``fetch_tx`` uses that set to switch
    to the V2 endpoint for those chains.

    Note: the legacy v1 endpoint (api.etherscan.io/api,
    api.bscscan.com/api, etc.) is now DEPRECATED and returns a JSON
    string ``result`` field with a migration warning instead of the
    expected tx object.  Whenever the unified ``ETHERSCAN_API_KEY`` is
    present the resolver routes the chain through V2 (even for
    ``ethereum`` itself) - per-chain legacy keys are still honoured for
    operators who explicitly set them.
    """
    env_map = env if env is not None else dict(os.environ)
    unified = env_map.get("ETHERSCAN_API_KEY", "")
    keys: dict[str, str] = {}
    blocked: list[str] = []
    v2_chains: set[str] = set()
    for chain, cfg in CHAIN_CONFIG.items():
        env_key = cfg["env_key"]
        v = env_map.get(env_key, "")
        # Per-chain legacy key wins.  The unified ETHERSCAN_API_KEY
        # always routes through V2 (even for ethereum) because the v1
        # endpoint is deprecated.
        if v and env_key != "ETHERSCAN_API_KEY":
            keys[chain] = v
        elif unified and cfg["family"] == "etherscan":
            keys[chain] = unified
            v2_chains.add(chain)
        elif v:
            # ETHERSCAN_API_KEY set + this IS the ethereum entry.
            keys[chain] = v
            if cfg["family"] == "etherscan":
                v2_chains.add(chain)
        else:
            keys[chain] = ""
            if cfg["family"] == "etherscan":
                blocked.append(chain)
    return keys, blocked, v2_chains


def append_trace_extraction(
    record_path: Path,
    record: dict[str, Any],
    trace_per_tx: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    """Mutate record in place + write back. Preserves verification_tier (R37)."""
    block = {
        "schema_version": SCHEMA_VERSION,
        "extractor": "tools/onchain-tx-deep-trace.py",
        "extracted_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "traces": trace_per_tx,
    }
    record["onchain_trace_extraction"] = block
    with record_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(record, fh, sort_keys=False, allow_unicode=True)


# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
def run(
    *,
    input_corpora: list[Path],
    top_n: int,
    sort_by: str,
    cursor_path: Path,
    output_mode: str,
    json_summary_path: Path | None,
    env: dict[str, str] | None = None,
    http_fn=None,
    resolve_selector: bool = True,
    rate_limit_per_sec: float | None = 5.0,
    daily_cap: int | None = 100_000,
) -> dict[str, Any]:
    """End-to-end orchestration. Returns the summary dict.

    ``rate_limit_per_sec`` clamps the COMBINED qps across all hosts
    (relevant for the V2 unified endpoint since the single key is shared
    across every chain).  ``daily_cap`` is the per-day max-call ceiling;
    once reached, in-flight requests return ``blocked_daily_cap`` and the
    run finishes early with the cursor's ``daily_used_today`` updated.
    """
    api_keys, blocked, v2_chains = resolve_api_keys(env=env)
    cursor = load_cursor(cursor_path)
    already = set(cursor.get("processed_tx_hashes") or [])

    # Daily-usage tracking lives on the cursor under ``daily_usage`` keyed
    # by UTC date.  When the day rolls over the counter resets to 0.
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily_usage = cursor.get("daily_usage") or {}
    if not isinstance(daily_usage, dict):
        daily_usage = {}
    daily_used_start = int(daily_usage.get(today, 0))

    all_record_paths = discover_corpus_records(input_corpora)
    loaded = [(p, load_record(p)) for p in all_record_paths]
    loaded_valid = [(p, r) for p, r in loaded if r is not None]

    candidates = rank_candidates(loaded_valid, top_n=top_n, sort_by=sort_by)

    throttle = HostThrottle(
        global_qps=rate_limit_per_sec,
        daily_cap=daily_cap,
        daily_used=daily_used_start,
    )
    chain_counter: dict[str, int] = defaultdict(int)
    tx_status_counter: dict[str, int] = defaultdict(int)
    records_updated = 0
    records_all_blocked = 0
    daily_cap_hit = False

    for path, rec in candidates:
        chain = get_chain_value(rec) or ""
        txs = get_tx_hashes(rec)
        per_tx: list[dict[str, Any]] = []
        any_ok = False
        for tx in txs:
            chain_counter[chain] += 1
            if tx in already:
                per_tx.append({"tx_hash": tx, "chain": chain, "fetch_status": "skipped_already_processed"})
                tx_status_counter["skipped_already_processed"] += 1
                continue
            trace = fetch_tx(
                chain,
                tx,
                api_keys,
                throttle=throttle,
                http_fn=http_fn,
                resolve_selector=resolve_selector,
                use_v2_chains=v2_chains,
            )
            per_tx.append(trace)
            st = trace.get("fetch_status", "unknown")
            tx_status_counter[st] += 1
            if st == "ok":
                already.add(tx)
                any_ok = True
            if st == "blocked_daily_cap":
                daily_cap_hit = True

        if txs and all(t.get("fetch_status") == "blocked_no_api_key" for t in per_tx):
            records_all_blocked += 1

        if output_mode == "append-to-record" and per_tx and any_ok:
            per_record_summary = {
                "chain": chain,
                "tx_count": len(per_tx),
                "ok_count": sum(1 for t in per_tx if t.get("fetch_status") == "ok"),
                "blocked_no_api_key_count": sum(1 for t in per_tx if t.get("fetch_status") == "blocked_no_api_key"),
                "fetch_error_count": sum(1 for t in per_tx if t.get("fetch_status") == "fetch_error"),
                "blocked_daily_cap_count": sum(1 for t in per_tx if t.get("fetch_status") == "blocked_daily_cap"),
            }
            append_trace_extraction(path, rec, per_tx, per_record_summary)
            records_updated += 1
        if daily_cap_hit:
            break

    cursor["processed_tx_hashes"] = sorted(already)
    cursor["blocked_no_api_key"] = sorted(blocked)
    daily_usage[today] = throttle.daily_used
    cursor["daily_usage"] = daily_usage
    cursor["daily_cap"] = daily_cap
    cursor["rate_limit_per_sec"] = rate_limit_per_sec
    cursor["v2_chains"] = sorted(v2_chains)
    save_cursor(cursor_path, cursor)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_corpora": [str(p) for p in input_corpora],
        "top_n_ceiling": top_n,
        "sort_by": sort_by,
        "candidates_selected": len(candidates),
        "candidate_chain_distribution": dict(chain_counter),
        "tx_fetch_status": dict(tx_status_counter),
        "records_updated_with_trace_block": records_updated,
        "records_all_blocked_no_api_key": records_all_blocked,
        "chains_blocked_no_api_key": sorted(blocked),
        "cursor_path": str(cursor_path),
        "output_mode": output_mode,
        "rate_limit_per_sec": rate_limit_per_sec,
        "daily_cap": daily_cap,
        "daily_used_today": throttle.daily_used,
        "daily_used_today_delta": throttle.daily_used - daily_used_start,
        "daily_cap_hit": daily_cap_hit,
        "v2_chains": sorted(v2_chains),
    }
    if json_summary_path is not None:
        json_summary_path.parent.mkdir(parents=True, exist_ok=True)
        json_summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fetch on-chain TX deep traces for the highest-impact incident records.",
    )
    p.add_argument(
        "--input-corpora",
        required=True,
        help="Comma-separated list of corpus directories (each holds <slug>/record.yaml).",
    )
    p.add_argument("--top-n", type=int, default=100, help="Operator-imposed ceiling (default 100).")
    p.add_argument("--sort-by", default="amount_usd", choices=["amount_usd"], help="Ranking key.")
    p.add_argument(
        "--cursor-path",
        default=".auditooor/external_intel_cursors/onchain_tx_trace.json",
        help="Resume cursor path.",
    )
    p.add_argument(
        "--output-mode",
        default="append-to-record",
        choices=["append-to-record", "summary-only"],
        help="append-to-record mutates record.yaml; summary-only is dry-run.",
    )
    p.add_argument("--json-summary", default=None, help="Optional path to write run summary JSON.")
    p.add_argument("--no-4byte", action="store_true", help="Skip 4byte.directory selector lookup.")
    p.add_argument("--print-json", action="store_true", help="Print run summary JSON to stdout.")
    # r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/onchain-tx-deep-trace.py
    p.add_argument(
        "--rate-limit-per-sec",
        type=float,
        default=5.0,
        help="Combined qps ceiling across ALL hosts (single shared key on the V2 unified endpoint). Default 5.0.",
    )
    p.add_argument(
        "--daily-cap",
        type=int,
        default=100_000,
        help="Per-day max-call ceiling. Once reached, in-flight requests return blocked_daily_cap and the run finishes early. Default 100000.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    corpora = [Path(p.strip()) for p in args.input_corpora.split(",") if p.strip()]
    summary = run(
        input_corpora=corpora,
        top_n=args.top_n,
        sort_by=args.sort_by,
        cursor_path=Path(args.cursor_path),
        output_mode=args.output_mode,
        json_summary_path=Path(args.json_summary) if args.json_summary else None,
        resolve_selector=not args.no_4byte,
        rate_limit_per_sec=args.rate_limit_per_sec,
        daily_cap=args.daily_cap,
    )
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
