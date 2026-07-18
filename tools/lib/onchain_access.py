#!/usr/bin/env python3
"""Loader for per-workspace on-chain access configuration.

A workspace that wants findings grounded on *live* chain state declares a small,
no-secrets config at ``<ws>/.auditooor/onchain_access.json``.  Findings-time
tools (``onchain-live-precondition-check.py`` and any future consumer) read this
loader instead of hardcoding an endpoint / addresses, so the same tool works
across cosmos-LCD and EVM-RPC targets by config alone.

Schema ``auditooor.onchain_access.v1``::

    {
      "schema": "auditooor.onchain_access.v1",
      "chain": "polygon" | "neutron" | "osmosis" | ...,
      "kind": "cosmos-lcd" | "evm-rpc",
      "endpoint": "https://public-no-auth-endpoint",   # read-only, NO api key
      "key_addresses": { "vaultMarker": "neutron1..." , "clob": "0xabc..." },
      "denom_usd": {
         "uusdc": {"source": "peg", "price_or_url": "1.0"},
         "untrn": {"source": "coingecko", "price_or_url": "https://api...."}
      }
    }

Only public, unauthenticated, read-only endpoints belong here.  This file MUST
NOT carry API keys, private keys, or any credential; ``validate_config`` rejects
obvious secret-bearing endpoints (``?apikey=`` / ``/v3/<hexkey>`` infura-style)
so a misconfiguration fails loud instead of leaking a secret into an artifact.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional


SCHEMA = "auditooor.onchain_access.v1"
VALID_KINDS = ("cosmos-lcd", "evm-rpc")
CONFIG_RELPATH = ".auditooor/onchain_access.json"

# Endpoints that clearly embed a credential.  We refuse these so a secret never
# lands in a committed verdict artifact and so "public no-auth" is enforced.
_SECRET_ENDPOINT_RE = re.compile(
    r"(?:[?&](?:api[_-]?key|apikey|key|token|access[_-]?token)=)"
    r"|(?:/v2/|/v3/)[0-9a-fA-F]{16,}"          # infura/alchemy style project key
    r"|@",                                       # basic-auth userinfo in URL
    re.IGNORECASE,
)


class OnchainAccessError(ValueError):
    """Raised when an onchain_access.json is present but malformed/unsafe."""


def config_path(workspace: str | Path) -> Path:
    """Return the canonical config path for a workspace root."""
    return Path(workspace) / CONFIG_RELPATH


def validate_config(cfg: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems; empty list == valid."""
    problems: list[str] = []
    if not isinstance(cfg, dict):
        return ["config is not a JSON object"]
    schema = cfg.get("schema")
    if schema and schema != SCHEMA:
        problems.append(f"unexpected schema {schema!r} (want {SCHEMA})")
    kind = cfg.get("kind")
    if kind not in VALID_KINDS:
        problems.append(f"kind must be one of {VALID_KINDS}, got {kind!r}")
    endpoint = str(cfg.get("endpoint") or "").strip()
    if not endpoint:
        problems.append("endpoint is required")
    else:
        if not re.match(r"^https?://", endpoint):
            problems.append("endpoint must be an http(s) URL")
        if _SECRET_ENDPOINT_RE.search(endpoint):
            problems.append(
                "endpoint appears to embed a credential; only public no-auth "
                "endpoints are allowed in onchain_access.json"
            )
    ka = cfg.get("key_addresses")
    if ka is not None and not isinstance(ka, dict):
        problems.append("key_addresses must be an object name->address")
    du = cfg.get("denom_usd")
    if du is not None and not isinstance(du, dict):
        problems.append("denom_usd must be an object denom->{source,price_or_url}")
    return problems


def load_onchain_access(
    workspace: str | Path, *, strict: bool = False
) -> Optional[dict[str, Any]]:
    """Load ``<ws>/.auditooor/onchain_access.json``.

    Returns the parsed config dict, or ``None`` when the file is absent (the
    common case: no live endpoint configured).  When ``strict`` is True, a
    malformed or unsafe config raises :class:`OnchainAccessError`; otherwise the
    problems are attached under ``_problems`` so callers can degrade to
    ``unverifiable`` instead of crashing.
    """
    path = config_path(workspace)
    if not path.is_file():
        return None
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise OnchainAccessError(f"unreadable {path}: {exc}") from exc
        return {"_problems": [f"unreadable {path}: {exc}"], "_path": str(path)}
    problems = validate_config(cfg)
    if problems:
        if strict:
            raise OnchainAccessError(
                f"invalid {path}: " + "; ".join(problems)
            )
        cfg = dict(cfg)
        cfg["_problems"] = problems
    cfg = dict(cfg)
    cfg["_path"] = str(path)
    return cfg


def resolve_address(cfg: dict[str, Any], name_or_addr: str) -> str:
    """Resolve a ``key_addresses`` symbol to a literal address.

    A raw address (``0x...`` or bech32-looking string) passes through
    unchanged; a bare symbol is looked up in ``key_addresses``.  Unknown symbols
    return the input untouched so the caller can emit a precise ``unverifiable``
    reason rather than silently querying a wrong address.
    """
    if not name_or_addr:
        return name_or_addr
    ka = cfg.get("key_addresses") or {}
    if name_or_addr in ka:
        return str(ka[name_or_addr])
    return name_or_addr
