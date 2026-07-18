#!/usr/bin/env python3
"""Dollar-impact model for auditooor toolkit.

Estimates the monetary impact of a security finding by cross-referencing
the target protocol's Total Value Locked (TVL) from DefiLlama with an
internal severity rubric.  Produces a deterministic JSON report containing:

  tvl_usd            - current TVL from DefiLlama (float)
  payout_tier_range  - {low, high} bounty payout percentages
  expected_bounty    - estimated USD payout (float)
  drill_cost_est     - estimated cost to drill/exploit (float)
  gate_verdict       - PROCEED / SKIP / INSUFFICIENT_DATA

All network access is best-effort; when DefiLlama is unreachable the tool
falls back to a workspace-cached value or emits INSUFFICIENT_DATA.

CLI:
  python3 tools/dollar-impact-model.py --workspace <path> \\
      --candidate-id <id> --output <path>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.dollar_impact.v1"
DEFILLAMA_API = "https://api.llama.fi"
CACHE_DIR = Path(".auditooor") / "dollar_impact_cache"
DEFAULT_TIMEOUT = 15  # seconds
BOUNTY_TIERS: list[dict[str, Any]] = [
    {"min_tvl": 1_000_000_000, "low_pct": 0.001,  "high_pct": 0.01},
    {"min_tvl":   100_000_000, "low_pct": 0.002,  "high_pct": 0.015},
    {"min_tvl":    10_000_000, "low_pct": 0.005,  "high_pct": 0.025},
    {"min_tvl":     1_000_000, "low_pct": 0.01,   "high_pct": 0.05},
    {"min_tvl":         0,     "low_pct": 0.02,   "high_pct": 0.10},
]

# Severity multipliers applied on top of the tier percentage.
SEVERITY_MULT: dict[str, float] = {
    "critical": 1.0,
    "high":     0.6,
    "medium":   0.25,
    "low":      0.05,
    "info":     0.01,
}

# Gate thresholds (USD).
GATE_PROCEED_MIN = 5_000.0
DRILL_COST_BASE = 2_500.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cache_path(workspace: Path, protocol_slug: str) -> Path:
    """Return the path to the cached TVL JSON for a given protocol."""
    return workspace / CACHE_DIR / f"{protocol_slug}.json"


def _http_get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Any:
    """Fetch *url* and return parsed JSON.  Raises on HTTP / decode errors."""
    req = urllib.request.Request(url, headers={"User-Agent": "auditooor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_protocol_tvl(protocol_slug: str, timeout: int = DEFAULT_TIMEOUT) -> float | None:
    """Return current TVL in USD for *protocol_slug* from DefiLlama.

    Returns ``None`` when the protocol is not found or the API is unreachable.
    """
    try:
        data = _http_get_json(
            f"{DEFILLAMA_API}/tvl/{protocol_slug}", timeout=timeout
        )
        if isinstance(data, (int, float)):
            return float(data)
        # Some endpoints return {"tvl": <number>}
        if isinstance(data, dict) and "tvl" in data:
            return float(data["tvl"])
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError):
        return None
    return None


def fetch_protocol_tvl_with_cache(
    workspace: Path,
    protocol_slug: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> float | None:
    """Fetch TVL, falling back to a workspace-local cache file."""
    tvl = fetch_protocol_tvl(protocol_slug, timeout=timeout)
    cpath = cache_path(workspace, protocol_slug)
    if tvl is not None:
        cpath.parent.mkdir(parents=True, exist_ok=True)
        cpath.write_text(json.dumps({"tvl_usd": tvl, "fetched_at": utc_now()}))
        return tvl
    # Fallback to cache
    if cpath.exists():
        try:
            cached = json.loads(cpath.read_text())
            return float(cached["tvl_usd"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            pass
    return None


def select_tier(tvl_usd: float) -> dict[str, float]:
    """Return the bounty-tier dict whose ``min_tvl`` <= *tvl_usd*."""
    for tier in BOUNTY_TIERS:
        if tvl_usd >= tier["min_tvl"]:
            return tier
    return BOUNTY_TIERS[-1]


def compute_bounty(
    tvl_usd: float,
    severity: str,
) -> dict[str, Any]:
    """Compute payout range, expected bounty, and drill cost."""
    tier = select_tier(tvl_usd)
    low_pct = tier["low_pct"]
    high_pct = tier["high_pct"]
    sev_mult = SEVERITY_MULT.get(severity.lower(), 0.10)

    low_bounty = tvl_usd * low_pct * sev_mult
    high_bounty = tvl_usd * high_pct * sev_mult
    expected_bounty = (low_bounty + high_bounty) / 2.0

    # Drill cost scales mildly with TVL but has a floor.
    drill_cost = DRILL_COST_BASE + (tvl_usd * 0.00001)

    return {
        "payout_tier_range": {"low_pct": low_pct, "high_pct": high_pct},
        "expected_bounty": round(expected_bounty, 2),
        "drill_cost_est": round(drill_cost, 2),
    }


def gate_verdict(expected_bounty: float) -> str:
    """Return PROCEED / SKIP based on expected bounty threshold."""
