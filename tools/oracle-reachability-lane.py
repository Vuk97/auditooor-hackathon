#!/usr/bin/env python3
"""oracle-reachability-lane.py  (ORL) - Oracle Price Reachability Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
ORL scans the function body for ORACLE / PRICE READS, then classifies each read
source as ATTACKER-MOVABLE vs GUARDED.

A read is ATTACKER-MOVABLE when it:
  - Queries raw AMM spot-reserves without a TWAP wrapper
    (Solidity: getReserves() / slot0() / observe() on a non-TWAP path)
  - Reads a single .price() interface with no staleness / bounds check
    (Solidity: IOracle.price() / IPriceFeed.price() / latestAnswer() /
     latestRoundData() WITHOUT round-id / staleness / minAnswer / maxAnswer)
  - Reads a Cosmos/Go oracle without a freshness check on the stored PriceState
    (Get*Price / GetReferencePrice / GetNetAssetValue / GetBandPrice /
     band_oracle / pyth_oracle / stork without a timestamp delta check)
  - Reads a CosmWasm / Rust oracle via a price query message with no
    freshness / bounds guard in the consuming function

A read is GUARDED (SKIP) when it:
  - Uses a recognised TWAP call: UniswapV3 OracleLibrary.consult / consult() /
    observe() with a non-zero secondsAgo / consult(pool, secondsAgo!=0)
  - Wraps Chainlink latestRoundData() / latestAnswer() WITH a staleness check:
    the function body also contains a time-freshness test (updatedAt /
    roundAge / heartbeat / MAX_DELAY / maxAge / stalenessThreshold / staleAfter
    / STALENESS / stale_after / freshness_threshold / latestRound / answeredInRound
    / minAnswer / maxAnswer / decimals / requiresAnswer) in the same function scope
  - Uses a multi-source median / aggregation pattern:
    median / aggregate / AggregatorV3 / getMultiplePrices / getPriceFromOracles /
    composite / checkAndGetTokensInWithPrice (Morpho multi-source)
  - Uses an explicit bounds check in the same function:
    maxPrice / minPrice / MAX_PRICE / MIN_PRICE / priceClamp / upperBound /
    lowerBound / price_bound / priceCap / sanityCheck / sanityBound

If a read is ATTACKER-MOVABLE AND the function is a VALUE-MOVING function (from
value_moving_functions.json), ORL emits ONE reachability hypothesis for the
(read_site, consuming_fn) pair.

NO FALSE-GREEN RULE
===================
ORL NEVER auto-confirms a finding. Every emitted record carries verdict="needs-fuzz".
Guarded reads MUST produce 0 hypotheses.

HYPOTHESIS SCHEMA
=================
{
  "workspace":           "<abs-path>",
  "file":                "<rel-path>",
  "function":            "<consuming-fn-name>",
  "language":            "sol|go|rs|move|cairo",
  "read_site":           "<rel-path>:<line-number>",
  "read_snippet":        "<the matching source line, stripped>",
  "read_kind":           "<oracle-type description>",
  "movability_reason":   "<why this source is attacker-movable>",
  "value_loss_path":     "<brief note on how the price drives value-loss>",
  "attack_class":        "oracle-price-manipulation",
  "sub_class":           "movable-spot|decimal-mismatch|l2-sequencer-grace",
  "source":              "ORL",
  "verdict":             "needs-fuzz"
}

SUB-CLASSES
===========
movable-spot      - existing class: price manipulable at the AMM/oracle level
decimal-mismatch  - latestRoundData()/latestAnswer() result used in math with a
                    hardcoded 1e8/1e18/decimals constant rather than calling
                    feed.decimals() - may silently mis-scale on non-8/18-decimal feeds
l2-sequencer-grace - Chainlink read on an L2 (Arbitrum/Optimism/Base) without an
                    L2 sequencer-uptime-feed + GRACE_PERIOD_TIME check

OUTPUT
======
<ws>/.auditooor/oracle_reachability_hypotheses.jsonl

CLI
===
  python3 tools/oracle-reachability-lane.py <workspace> [--out <path>]
  --vmf-json:   override value_moving_functions.json path
  --regen-vmf:  re-run value-moving-functions.py even if JSON exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# OOS guard (single source of truth).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

# ---------------------------------------------------------------------------
# Lazy-load value-moving-functions module.
# ---------------------------------------------------------------------------
_VMF_MOD_NAME = "value_moving_functions_orl_import"
_VMF_PATH = Path(__file__).resolve().parent / "value-moving-functions.py"


def _load_vmf_module():
    spec = importlib.util.spec_from_file_location(_VMF_MOD_NAME, _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_VMF_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF: Any = None


def _vmf() -> Any:
    global _VMF
    if _VMF is None:
        _VMF = _load_vmf_module()
    return _VMF


# ---------------------------------------------------------------------------
# ORACLE READ PATTERNS (per language).
#
# Each entry is (pattern, read_kind, movability_reason).
# Applied to the extracted function-body text.
# ---------------------------------------------------------------------------

# Solidity oracle read patterns (attacker-movable candidates).
_SOL_ORACLE_READ: list[tuple[re.Pattern, str, str]] = [
    # Uniswap V2: getReserves() - raw spot reserves, flash-loan manipulable
    (
        re.compile(r"\bgetReserves\s*\(", re.I),
        "uniswap-v2-spot-reserves",
        "raw AMM spot reserves - manipulable via flash loan in a single block",
    ),
    # Uniswap V3: slot0() - current tick/sqrtPrice, flash-loan manipulable
    (
        re.compile(r"\bslot0\s*\(", re.I),
        "uniswap-v3-slot0-spot",
        "raw UniswapV3 slot0 current tick - manipulable via flash loan in a single block",
    ),
    # IOracle / IPriceFeed single .price() call (Morpho-style, admin-settable oracle)
    (
        re.compile(r"\.\s*price\s*\(\s*\)", re.I),
        "ioracle-single-price",
        "single price() view with no staleness/bounds fields - oracle contract is admin/permissionlessly settable",
    ),
    # Chainlink latestAnswer() - no staleness checked at read site
    (
        re.compile(r"\blatestAnswer\s*\(", re.I),
        "chainlink-latestAnswer",
        "Chainlink latestAnswer() without staleness or round check - may return stale/manipulated price",
    ),
    # Chainlink latestRoundData() - needs freshness check to be guarded
    (
        re.compile(r"\blatestRoundData\s*\(", re.I),
        "chainlink-latestRoundData",
        "Chainlink latestRoundData() - guarded only if updatedAt/answeredInRound/minAnswer/maxAnswer checked",
    ),
    # getPriceUnsafe / getPrice (Pyth unsafe)
    (
        re.compile(r"\bgetPriceUnsafe\s*\(", re.I),
        "pyth-getPriceUnsafe",
        "Pyth getPriceUnsafe() - explicitly skips confidence and age validation",
    ),
]

# Go / Cosmos oracle read patterns.
_GO_ORACLE_READ: list[tuple[re.Pattern, str, str]] = [
    # Generic oracle keeper GetPrice / GetReferencePrice / GetBandReferencePrice
    (
        re.compile(r"\bk\s*\.\s*oracle\s*\.\s*Get\w*Price\s*\(", re.I),
        "cosmos-oracle-GetPrice",
        "cosmos oracle keeper Get*Price without freshness check on stored PriceState",
    ),
    (
        re.compile(r"\bGetReferencePrice\s*\(", re.I),
        "cosmos-oracle-GetReferencePrice",
        "cosmos GetReferencePrice routes to band/pyth/stork stored state with no freshness guard",
    ),
    (
        re.compile(r"\bGetBandReferencePrice\s*\(", re.I),
        "cosmos-band-oracle",
        "Band oracle price read from stored BandPriceState with no staleness/timestamp delta check",
    ),
    # Marker NAV / GetNetAssetValue (Injective/similar)
    (
        re.compile(r"\bGetNetAssetValue\s*\(", re.I),
        "cosmos-marker-NAV",
        "marker NAV GetNetAssetValue - admin/permissionlessly settable NAV with no bounds check",
    ),
    (
        re.compile(r"\bGetMarkerPrice\s*\(", re.I),
        "cosmos-marker-price",
        "cosmos marker price read - admin-settable without bounds enforcement",
    ),
    # Pyth keeper
    (
        re.compile(r"\bGetPythPrice\s*\(", re.I),
        "cosmos-pyth-price",
        "Pyth price from keeper store - guarded only with explicit confidence/age check",
    ),
    # Generic GetPrice on an oracle-named keeper receiver only.
    # Require the call to be preceded by an oracle-receiver identifier (oracle., OracleKeeper.,
    # k.oracle., etc.) to avoid matching order/market struct methods (order.GetPrice()).
    (
        re.compile(r"\boracle\w*\s*\.\s*GetPrice\s*\(|\bOracleKeeper\s*\.\s*GetPrice\s*\(", re.I),
        "cosmos-oracle-generic-GetPrice",
        "generic GetPrice from oracle keeper - guarded only with explicit freshness check",
    ),
    # ---- Cosmos exchange-rate oracle idioms (FIX-3 class A) ----
    # Sei x/oracle keeper.GetBaseExchangeRate(denom) - reads the stored
    # OracleExchangeRate (rate + LastUpdate + LastUpdateTimestamp); the value is
    # attacker/staleness-relevant unless the CONSUMER checks LastUpdateTimestamp.
    (
        re.compile(r"\bGetBaseExchangeRate\s*\(", re.I),
        "cosmos-oracle-GetBaseExchangeRate",
        "sei x/oracle GetBaseExchangeRate stored OracleExchangeRate - guarded only if consumer checks LastUpdate/LastUpdateTimestamp staleness",
    ),
    # Generic <keeper>.GetExchangeRate / GetExchangeRateWithDenom (Injective / Sei-family)
    (
        re.compile(r"\bGetExchangeRate(?:WithDenom)?\s*\(", re.I),
        "cosmos-oracle-GetExchangeRate",
        "cosmos oracle GetExchangeRate[WithDenom] stored rate - guarded only with explicit freshness/timestamp-delta check",
    ),
    # Slinky x/oracle GetPriceForCurrencyPair - stored QuotePrice + BlockTimestamp
    (
        re.compile(r"\bGetPriceForCurrencyPair\s*\(", re.I),
        "cosmos-slinky-GetPriceForCurrencyPair",
        "Slinky GetPriceForCurrencyPair stored QuotePrice - guarded only if BlockTimestamp/BlockHeight age of the price is validated",
    ),
    # Generic oracle-keeper price getter: <oracleRecv>.Get<...>Price(...) or
    # <oracleRecv>.Get<...>ExchangeRate(...) where the receiver is oracle-named.
    # Kept receiver-anchored to avoid matching unrelated struct getters.
    (
        re.compile(
            r"\b(?:oracle\w*|OracleKeeper|OracleK|ok|priceKeeper|PriceKeeper)\s*\.\s*"
            r"Get\w*(?:Price|ExchangeRate)\w*\s*\(",
            re.I,
        ),
        "cosmos-oracle-keeper-price-getter",
        "oracle keeper price/exchange-rate getter - guarded only with explicit freshness/bounds check in the value-moving consumer",
    ),
]

# Rust / CosmWasm oracle read patterns.
_RS_ORACLE_READ: list[tuple[re.Pattern, str, str]] = [
    # CosmWasm oracle query
    (
        re.compile(r"\bOracleQuery\s*::", re.I),
        "cosmwasm-oracle-query",
        "CosmWasm oracle query msg - guarded only with explicit age/confidence check in consumer",
    ),
    (
        re.compile(r"\bquery_oracle\s*\(", re.I),
        "cosmwasm-query-oracle",
        "CosmWasm query_oracle call - guarded only with explicit freshness/bounds check",
    ),
    # Pyth SDK price feed
    (
        re.compile(r"\bprice_feed\s*\.\s*get_price\b", re.I),
        "pyth-rs-get_price",
        "Pyth price_feed.get_price() - guarded only with explicit age/confidence check",
    ),
    (
        re.compile(r"\bget_price_unchecked\s*\(", re.I),
        "pyth-rs-unchecked",
        "Pyth get_price_unchecked() - explicitly skips confidence and age validation",
    ),
    # Generic oracle trait
    (
        re.compile(r"\bOracle\s*::\s*price\s*\(", re.I),
        "rs-oracle-price",
        "oracle trait price() call - guarded only with explicit staleness/bounds check",
    ),
]

_LANG_ORACLE_READS: dict[str, list[tuple[re.Pattern, str, str]]] = {
    "sol": _SOL_ORACLE_READ,
    "go": _GO_ORACLE_READ,
    "rs": _RS_ORACLE_READ,
    # Move / Cairo: extend as patterns emerge
    "move": [],
    "cairo": [],
}

# ---------------------------------------------------------------------------
# SUB-CLASS CLASSIFIERS
# ---------------------------------------------------------------------------
# These patterns fire AFTER the main oracle-read detection, on the function
# body, to assign a finer sub_class label to each hypothesis.
# They are checked independently of the guard-pattern system (a read can be
# both unguarded AND have a decimal-mismatch, for instance).

# ORACLE-DECIMAL-MISMATCH (Solidity only):
# The function body uses a Chainlink price read AND contains a hardcoded
# decimal scale constant (1e8 / 1e18 / 10**8 / 10**18 / 1e6 / 10**6 etc.)
# WITHOUT calling feed.decimals() to obtain the actual scale.
_SOL_HARDCODED_DECIMAL_PATS: list[re.Pattern] = [
    re.compile(r"\b1e8\b"),
    re.compile(r"\b1e18\b"),
    re.compile(r"\b1e6\b"),
    re.compile(r"\b10\s*\*\*\s*8\b"),
    re.compile(r"\b10\s*\*\*\s*18\b"),
    re.compile(r"\b10\s*\*\*\s*6\b"),
    # Common named constant patterns like PRICE_SCALE = 1e8, DECIMALS = 8
    re.compile(r"\bPRICE_SCALE\b", re.I),
    re.compile(r"\bDECIMALS\s*=\s*\d", re.I),
    re.compile(r"\bDECIMAL_FACTOR\b", re.I),
    re.compile(r"\bSCALE\s*=\s*1e", re.I),
]

# Pattern that signals the code DOES call feed.decimals() - safe, not a mismatch.
_SOL_FEED_DECIMALS_PAT = re.compile(r"\.\s*decimals\s*\(", re.I)

# Chainlink price-read patterns (subset of _SOL_ORACLE_READ) to identify
# which hypotheses are candidates for decimal-mismatch classification.
_SOL_CHAINLINK_PRICE_READ_PATS: set[str] = {
    "chainlink-latestAnswer",
    "chainlink-latestRoundData",
}

# L2-SEQUENCER-GRACE (Solidity only):
# The function body uses a Chainlink price read but does NOT have a
# sequencerUptimeFeed / GRACE_PERIOD_TIME check in the same function scope.
# Applies to Arbitrum / Optimism / Base deployments.
_SOL_SEQUENCER_GUARD_PATS: list[re.Pattern] = [
    re.compile(r"\bsequencerUptimeFeed\b", re.I),
    re.compile(r"\bsequencer_uptime\b", re.I),
    re.compile(r"\bGRACE_PERIOD_TIME\b", re.I),
    re.compile(r"\bgracePeriod\b", re.I),
    re.compile(r"\bsequencerFeed\b", re.I),
    re.compile(r"\buptimeFeed\b", re.I),
    re.compile(r"\bL2SequencerFeed\b", re.I),
]


def _sol_sub_class(body: str, read_kind: str) -> str:
    """Return the sub_class label for a Solidity oracle read hypothesis.

    Evaluated in priority order:
    1. decimal-mismatch  - Chainlink read with hardcoded scale, no feed.decimals()
    2. l2-sequencer-grace - Chainlink read without sequencer uptime guard
    3. movable-spot      - default (existing behaviour)

    Only checks decimal-mismatch and l2-sequencer-grace for Chainlink reads;
    AMM reads always get movable-spot.
    """
    if read_kind not in _SOL_CHAINLINK_PRICE_READ_PATS:
        return "movable-spot"

    # decimal-mismatch: hardcoded scale present AND no feed.decimals() call.
    if not _SOL_FEED_DECIMALS_PAT.search(body):
        for pat in _SOL_HARDCODED_DECIMAL_PATS:
            if pat.search(body):
                return "decimal-mismatch"

    # l2-sequencer-grace: no sequencer uptime feed check in scope.
    has_sequencer_guard = any(p.search(body) for p in _SOL_SEQUENCER_GUARD_PATS)
    if not has_sequencer_guard:
        return "l2-sequencer-grace"

    return "movable-spot"

# ---------------------------------------------------------------------------
# GUARD PATTERNS (per language).
#
# If ANY guard pattern fires in the same function body, the oracle read is
# classified as GUARDED -> SKIP.
# ---------------------------------------------------------------------------

# Solidity guards.
_SOL_GUARDS: list[re.Pattern] = [
    # TWAP: OracleLibrary.consult / consult(secondsAgo) with non-zero duration
    re.compile(r"\bconsult\s*\(", re.I),
    re.compile(r"\bsecondsAgo\b"),
    # Chainlink freshness: updatedAt, answeredInRound, heartbeat, delay checks
    re.compile(r"\bupdatedAt\b"),
    re.compile(r"\bansweredInRound\b"),
    re.compile(r"\bMAX_DELAY\b"),
    re.compile(r"\bmaxAge\b", re.I),
    re.compile(r"\bstalenessThreshold\b", re.I),
    re.compile(r"\bstaleAfter\b", re.I),
    re.compile(r"\bSTALENESS\b"),
    re.compile(r"\bfreshness_threshold\b", re.I),
    re.compile(r"\bhearBeat\b", re.I),
    re.compile(r"\bheartbeat\b", re.I),
    # Bounds checks
    re.compile(r"\bminAnswer\b"),
    re.compile(r"\bmaxAnswer\b"),
    re.compile(r"\bMAX_PRICE\b"),
    re.compile(r"\bMIN_PRICE\b"),
    re.compile(r"\bmaxPrice\b", re.I),
    re.compile(r"\bminPrice\b", re.I),
    re.compile(r"\bpriceClamp\b", re.I),
    re.compile(r"\bpriceCap\b", re.I),
    re.compile(r"\bsanityBound\b", re.I),
    re.compile(r"\bsanityCheck\b", re.I),
    # Multi-source median / aggregation
    re.compile(r"\bmedian\s*\(", re.I),
    re.compile(r"\baggregate\s*\(", re.I),
    re.compile(r"\bgetMultiplePrices\b", re.I),
    # TWAP specific wrappers
    re.compile(r"\bTWAP\b", re.I),
    re.compile(r"\btwapPrice\b", re.I),
    re.compile(r"\btwap_price\b", re.I),
    # Uniswap V3 TWAP oracle path (not slot0)
    re.compile(r"\bobserve\s*\("),
]

# Go / Cosmos guards.
_GO_GUARDS: list[re.Pattern] = [
    # Timestamp delta / freshness check
    re.compile(r"\bLastUpdatedTime\b"),
    re.compile(r"\bupdatedAt\b"),
    re.compile(r"\bResolveTime\b"),
    re.compile(r"\bMaxAge\b", re.I),
    re.compile(r"\bmaxAge\b"),
    re.compile(r"\bfreshnessThreshold\b", re.I),
    re.compile(r"\bstaleness\b", re.I),
    re.compile(r"\bIsStale\b", re.I),
    re.compile(r"\bExpiry\b"),
    re.compile(r"\bBlockTime\b.*\bLastUpdated\b"),
    # ---- Cosmos exchange-rate staleness idioms (FIX-3 class A guards) ----
    # sei OracleExchangeRate.LastUpdate / LastUpdateTimestamp compared against
    # ctx.BlockHeight()/BlockTime() to bound the age of the served rate.
    re.compile(r"\bLastUpdateTimestamp\b"),
    re.compile(r"\bLastUpdate\b.*\bBlock(?:Time|Height)\b"),
    re.compile(r"\bBlock(?:Time|Height)\b.*\bLastUpdate\b"),
    # Slinky QuotePrice freshness (BlockTimestamp/BlockHeight age of the price)
    re.compile(r"\bBlockTimestamp\b.*\b(?:Age|Stale|Max)\b", re.I),
    re.compile(r"\bGetPriceAge\b", re.I),
    re.compile(r"\bValidatePriceIsValid\b", re.I),
    re.compile(r"\bPriceIsValid\b", re.I),
    # Explicit freshness/heartbeat window comparisons
    re.compile(r"\bstalePriceThreshold\b", re.I),
    re.compile(r"\bpriceMaxAge\b", re.I),
    re.compile(r"\bmaxPriceAge\b", re.I),
    # Bounds
    re.compile(r"\bMinPrice\b"),
    re.compile(r"\bMaxPrice\b"),
    re.compile(r"\bPriceCap\b", re.I),
    # TWAP
    re.compile(r"\bTWAP\b", re.I),
    re.compile(r"\btwapPrice\b", re.I),
    # Multi-source aggregation
    re.compile(r"\bMedian\b", re.I),
    re.compile(r"\bAggregate\b", re.I),
]

# Rust / CosmWasm guards.
_RS_GUARDS: list[re.Pattern] = [
    re.compile(r"\bpublish_time\b"),
    re.compile(r"\bexpo\b.*\bconf\b"),
    re.compile(r"\bconf\b.*\bprice\b"),
    re.compile(r"\bage\b", re.I),
    re.compile(r"\bmax_age\b", re.I),
    re.compile(r"\bfreshness\b", re.I),
    re.compile(r"\bstaleness\b", re.I),
    re.compile(r"\bmin_price\b", re.I),
    re.compile(r"\bmax_price\b", re.I),
    re.compile(r"\bprice_bound\b", re.I),
    re.compile(r"\btwap\b", re.I),
    re.compile(r"\bmedian\b", re.I),
]

_LANG_GUARDS: dict[str, list[re.Pattern]] = {
    "sol": _SOL_GUARDS,
    "go": _GO_GUARDS,
    "rs": _RS_GUARDS,
    "move": [],
    "cairo": [],
}

# ---------------------------------------------------------------------------
# VALUE-LOSS PATH NOTES per read kind.
# ---------------------------------------------------------------------------
_VALUE_LOSS_NOTES: dict[str, str] = {
    "uniswap-v2-spot-reserves":   "spot reserves used as price for collateral/liquidation valuation; flash-loan manipulation => over/under-valuation",
    "uniswap-v3-slot0-spot":      "slot0 sqrtPriceX96 used as price; flash-loan manipulation inflates/deflates collateral value",
    "ioracle-single-price":       "single .price() result drives collateral valuation (maxDebt / seizedAssets); manipulable oracle => fund extraction",
    "chainlink-latestAnswer":     "stale / manipulated latestAnswer propagates into collateral or liquidation math",
    "chainlink-latestRoundData":  "latestRoundData without freshness guard - stale price drives value-moving arithmetic",
    "pyth-getPriceUnsafe":        "unsafe Pyth price skips confidence and age checks; stale/outlier price drives collateral math",
    "cosmos-oracle-GetPrice":     "cosmos oracle GetPrice stored value - no freshness delta check; stale/admin-set price drives liquidation",
    "cosmos-oracle-GetReferencePrice": "GetReferencePrice from stored state - nil/non-positive check only; stale price drives margin math",
    "cosmos-band-oracle":         "Band oracle PriceState - no timestamp delta check; stale price drives liquidation threshold",
    "cosmos-marker-NAV":          "unbounded marker NAV - admin-settable; consumed in valuation => overflow or artificial under/over-collateralisation",
    "cosmos-marker-price":        "admin-settable marker price without bounds; drives value-moving arithmetic",
    "cosmos-pyth-price":          "Pyth price from keeper without confidence/age check; stale outlier drives fund loss",
    "cosmos-oracle-generic-GetPrice": "generic keeper GetPrice - guarded only if explicit freshness check follows in scope",
    "cosmos-oracle-GetBaseExchangeRate": "sei x/oracle base exchange rate consumed on a value path without a LastUpdateTimestamp staleness gate; stale/manipulated rate mis-values collateral/fees",
    "cosmos-oracle-GetExchangeRate": "cosmos oracle exchange rate read without timestamp-delta freshness check; stale rate drives value-moving conversion",
    "cosmos-slinky-GetPriceForCurrencyPair": "Slinky stored QuotePrice consumed without validating BlockTimestamp/BlockHeight age; stale price drives value-moving arithmetic",
    "cosmos-oracle-keeper-price-getter": "oracle-keeper price/exchange-rate getter consumed on a value path without a freshness/bounds guard; stale or admin-set price drives value loss",
    "cosmwasm-oracle-query":      "CosmWasm oracle query without age/confidence check in consumer; stale price drives value transfer",
    "cosmwasm-query-oracle":      "CosmWasm query_oracle without freshness/bounds guard; drives value-moving arithmetic",
    "pyth-rs-get_price":          "Pyth price_feed.get_price() without age/confidence gate; stale price drives fund movement",
    "pyth-rs-unchecked":          "Pyth get_price_unchecked() explicitly skips all validation; stale/outlier price drives value path",
    "rs-oracle-price":            "oracle trait price() without staleness/bounds check; drives value-moving path",
}


# ---------------------------------------------------------------------------
# Function body extractor (reuses VMF logic).
# ---------------------------------------------------------------------------

def _extract_fn_body(source: str, fn_match: re.Match) -> tuple[str, int]:
    """Extract the text block starting from fn_match to the matching brace end.

    Returns (body_text, start_line_number_of_fn).
    start_line = 1-indexed line where the function signature starts.
    """
    start = fn_match.start()
    start_line = source[:start].count("\n") + 1
    # Find opening brace after the signature.
    brace_pos = source.find("{", fn_match.end())
    if brace_pos == -1:
        # No brace found (e.g. interface or abstract fn) - return signature line only.
        end_pos = source.find(";", fn_match.end())
        if end_pos == -1:
            end_pos = min(start + 500, len(source))
        return source[start:end_pos], start_line
    depth = 1
    pos = brace_pos + 1
    while pos < len(source) and depth > 0:
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        pos += 1
    return source[start:pos], start_line


def _line_number(source: str, match_start: int) -> int:
    """Return 1-indexed line number for a byte offset in source."""
    return source[:match_start].count("\n") + 1


# ---------------------------------------------------------------------------
# Core per-function oracle read detection.
# ---------------------------------------------------------------------------

def _is_guarded(body: str, lang: str) -> bool:
    """Return True if any guard pattern fires in ``body``."""
    for pat in _LANG_GUARDS.get(lang, []):
        if pat.search(body):
            return True
    return False


# ---------------------------------------------------------------------------
# INTER-PROCEDURAL Go extension (FIX-3 class B).
#
# The intra-procedural scan misses oracle reads that live inside keeper/helper
# methods called by a value-moving function - e.g. nuva's
# ``k.MarkerKeeper.GetNetAssetValue`` read inside ``UnitPriceFraction``, which is
# reached from the value-moving ``SwapIn``/``SwapOut`` via
# ``ToUnderlyingAssetAmount`` -> ``UnitPriceFraction``. Following call-hops into
# those helpers surfaces the real Critical source.
#
# Design:
#   * A workspace-wide Go method-body index (name -> [ {file_rel, start, body} ])
#     is built once per run and cached.
#   * From each value-moving Go function we follow method-call edges up to
#     ``_GO_MAX_HOPS`` hops, scanning each reached helper body for the same oracle
#     read idioms.
#   * The GUARD scope for an inter-procedural read is the UNION of the call-path
#     bodies (VMF body + every intermediate helper + the read-containing helper):
#     if any function on the path applies a freshness/bounds guard the read is
#     treated as guarded (conservative - avoids false positives when the caller
#     clamps the price).
# ---------------------------------------------------------------------------

# The broad "oracle keeper price getter" idiom is a CATCH-ALL: when an
# oracle-named receiver calls a Get*Price/Get*ExchangeRate method it also matches
# the same read site that a more-specific idiom (GetBaseExchangeRate, Slinky, ...)
# already fired on. To avoid two rows for one read, the generic kind is emitted
# only as a per-read-site fallback (when no specific idiom already covered that
# exact site). Gating ONLY this new kind keeps existing idiom emit counts intact.
_GO_GENERIC_GETTER_KIND = "cosmos-oracle-keeper-price-getter"

# Default hop budget. nuva's Critical read sits 2 helper-hops below SwapIn
# (SwapIn -> ToUnderlyingAssetAmount -> UnitPriceFraction[read]); 3 gives margin
# for one extra indirection without exploding the search.
_GO_MAX_HOPS = 3

# Per-value-moving-function ceiling on the number of distinct helper methods the
# inter-procedural BFS will visit. Huge cosmos monorepos (sei, polygon) have call
# graphs with tens of thousands of reachable methods; without a bound the 255-VMF
# fan-out is O(minutes). All real oracle-read chains observed on the fleet sit
# within a handful of hops of a small helper set, so a generous cap keeps the run
# bounded while never truncating a genuine short chain.
_GO_INTERPROC_VISIT_BUDGET = 6000

# Callee-name extractor for Go: matches the method/function identifier that is
# immediately applied ("(") - captures the final selector name so that
# ``k.MarkerKeeper.GetNetAssetValue(`` yields ``GetNetAssetValue`` and
# ``k.UnitPriceFraction(`` yields ``UnitPriceFraction``. Only names present in
# the workspace method index are followed, so built-ins / stdlib calls are
# harmlessly ignored.
_GO_CALLEE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

# Go control-keywords that _GO_CALLEE_RE would otherwise capture as pseudo-calls
# (`if (`, `for (`, `switch (` ...). Never resolved as helpers, but skipping them
# keeps the frontier small.
_GO_CALL_STOPWORDS = frozenset({
    "if", "for", "switch", "return", "func", "go", "defer", "select",
    "make", "len", "cap", "append", "panic", "recover", "new", "copy",
    "range", "case", "else", "int", "uint", "string", "bool", "byte",
})

# Per-workspace cache of the Go helper index. Keyed by resolved workspace path.
_GO_HELPER_INDEX_CACHE: dict[str, tuple[dict[str, list[dict[str, Any]]], dict[str, str]]] = {}


def _go_callees(body: str) -> set[str]:
    """Return the set of candidate callee identifiers applied in ``body``."""
    out: set[str] = set()
    for m in _GO_CALLEE_RE.finditer(body):
        name = m.group(1)
        if name in _GO_CALL_STOPWORDS:
            continue
        out.add(name)
    return out


def _build_go_helper_index(
    ws: Path,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    """Build (method_index, file_sources) for every in-scope Go function in ``ws``.

    method_index: fn_name -> list of per-def dicts. Each def PRE-COMPUTES the
    fields the inter-procedural BFS needs so the hot loop performs only cheap dict
    lookups (no regex) - essential on huge cosmos monorepos:
        {
          "file_rel":    relative path,
          "start":       fn-signature byte offset in the file source,
          "callees":     frozenset of callee identifiers in this body,
          "has_guard":   True if any Go freshness/bounds guard fires in this body,
          "oracle_hits": list of (read_kind, movability_reason, match_start) for
                         each distinct oracle-read idiom that fires in this body,
        }
    file_sources: file_rel -> full source text (only for files that hold >=1 fn).

    Cached per workspace so the walk + pattern precompute run once per ORL run.
    """
    key = str(ws)
    cached = _GO_HELPER_INDEX_CACHE.get(key)
    if cached is not None:
        return cached

    fn_re = _vmf()._FN_RES.get("go")
    go_oracle_pats = _LANG_ORACLE_READS.get("go", [])
    go_guards = _LANG_GUARDS.get("go", [])
    method_index: dict[str, list[dict[str, Any]]] = {}
    file_sources: dict[str, str] = {}
    if fn_re is not None:
        for gf in ws.rglob("*.go"):
            try:
                rel = str(gf.relative_to(ws))
            except ValueError:
                continue
            if is_oos(rel):
                continue
            try:
                src = gf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            has_fn = False
            for m in fn_re.finditer(src):
                name = m.group(1)
                body, _ = _extract_fn_body(src, m)
                has_guard = any(p.search(body) for p in go_guards)
                oracle_hits: list[tuple[str, str, int]] = []
                seen_local: set[str] = set()
                for pat, read_kind, reason in go_oracle_pats:
                    if read_kind in seen_local:
                        continue
                    mm = pat.search(body)
                    if mm:
                        oracle_hits.append((read_kind, reason, mm.start()))
                        seen_local.add(read_kind)
                method_index.setdefault(name, []).append({
                    "file_rel":    rel,
                    "start":       m.start(),
                    "callees":     frozenset(_go_callees(body)),
                    "has_guard":   has_guard,
                    "oracle_hits": oracle_hits,
                })
                has_fn = True
            if has_fn:
                file_sources[rel] = src

    _GO_HELPER_INDEX_CACHE[key] = (method_index, file_sources)
    return method_index, file_sources


def _detect_go_interproc_reads(
    vmf_name: str,
    vmf_body: str,
    method_index: dict[str, list[dict[str, Any]]],
    file_sources: dict[str, str],
    seen_kinds: set[str],
    seen_sites: set[str] | None = None,
    max_hops: int = _GO_MAX_HOPS,
    visit_budget: int = _GO_INTERPROC_VISIT_BUDGET,
) -> list[dict[str, Any]]:
    """Follow call-hops from a value-moving Go fn into helper bodies.

    Oracle-read matches and guard status for each helper body are read from the
    pre-computed ``method_index`` (see ``_build_go_helper_index``) so this hot
    loop performs only dict lookups. Emits ONE hypothesis per (read_kind) reached,
    attributed to the value-moving consumer ``vmf_name`` but with ``read_site``
    pointing at the helper source. ``seen_kinds`` is shared with the intra-
    procedural pass so a kind already emitted for this fn is not duplicated.

    The GUARD scope for an inter-procedural read is the UNION of the call-path
    bodies: if ANY function on the path (VMF -> ... -> read helper) applies a
    freshness/bounds guard the read is treated as guarded. This is realised by
    NOT expanding the BFS through a guarded def (so its descendants keep a guarded
    ancestor out of every path that flows through it) and by suppressing the read
    of a guarded def itself. A read is therefore emitted iff at least one path
    from the value-moving fn to the read helper is guard-free end to end - path
    order can never hide a genuine unguarded reach.
    """
    hyps: list[dict[str, Any]] = []
    if seen_sites is None:
        seen_sites = set()
    # Never recurse into the VMF itself (its body is handled intra-procedurally).
    visited: set[str] = {vmf_name}
    # The VMF body reaching here is unguarded (guarded VMFs early-exit before
    # interproc), so every frontier seed starts on a guard-free path.
    # BFS (FIFO) so every method is discovered at its MINIMUM hop distance. A DFS
    # (LIFO) with a global visited set + depth limit can discover an intermediate
    # helper first at a too-deep hop (where it is not expanded), which would block
    # the shallower productive path to the read and drop a genuine finding.
    frontier: deque[tuple[str, int]] = deque(
        (callee, 1) for callee in _go_callees(vmf_body)
    )

    while frontier:
        if len(visited) >= visit_budget:
            break
        name, hop = frontier.popleft()
        if name in visited or hop > max_hops:
            continue
        visited.add(name)
        defs = method_index.get(name)
        if not defs:
            continue
        for d in defs:
            # A guard anywhere on the path (this def included) makes the read
            # non-attacker-movable: skip its reads AND do not expand through it.
            if d["has_guard"]:
                continue
            for read_kind, movability_reason, match_start in d["oracle_hits"]:
                if read_kind in seen_kinds:
                    continue
                helper_rel = d["file_rel"]
                helper_src = file_sources.get(helper_rel, "")
                abs_offset = d["start"] + match_start
                read_line = _line_number(helper_src, abs_offset) if helper_src else 0
                read_site = f"{helper_rel}:{read_line}"
                # Generic getter is a per-site fallback (see intra-procedural pass).
                if read_kind == _GO_GENERIC_GETTER_KIND and read_site in seen_sites:
                    continue
                seen_kinds.add(read_kind)
                seen_sites.add(read_site)
                src_lines = helper_src.splitlines()
                read_snippet = (
                    src_lines[read_line - 1].strip()
                    if 0 < read_line <= len(src_lines)
                    else ""
                )
                hyps.append({
                    "workspace":         "",  # filled by caller
                    "file":              helper_rel,
                    "function":          vmf_name,
                    "language":          "go",
                    "read_site":         read_site,
                    "read_snippet":      read_snippet,
                    "read_kind":         read_kind,
                    "movability_reason": (
                        f"{movability_reason} [inter-procedural: read in helper "
                        f"'{name}' reached from value-moving '{vmf_name}' within "
                        f"{hop} hop(s)]"
                    ),
                    "value_loss_path":   _VALUE_LOSS_NOTES.get(
                        read_kind, "price drives value-moving arithmetic"
                    ),
                    "attack_class":      "oracle-price-manipulation",
                    "sub_class":         "movable-spot",
                    "source":            "ORL",
                    "verdict":           "needs-fuzz",
                    # Additive inter-procedural provenance fields (existing readers
                    # ignore unknown JSONL keys; intra-procedural rows are unchanged).
                    "interprocedural":   True,
                    "read_fn":           name,
                    "call_hops":         hop,
                })
            # Recurse deeper along this (still guard-free) path regardless of a
            # hit - a later kind may live below - bounded by max_hops.
            if hop < max_hops:
                for callee in d["callees"]:
                    if callee not in visited:
                        frontier.append((callee, hop + 1))  # noqa: PERF401

    return hyps


def detect_oracle_reads(
    source: str,
    language: str,
    fn_name: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/orl_fixture_ws",
    go_helper_index: dict[str, list[dict[str, Any]]] | None = None,
    go_file_sources: dict[str, str] | None = None,
    go_max_hops: int = _GO_MAX_HOPS,
) -> list[dict[str, Any]]:
    """Detect attacker-movable oracle reads in a single function.

    Returns a list of hypothesis dicts (may be empty).
    This is the primary unit-testable entry point.

    ``source`` must contain the full function definition.

    When ``language == "go"`` and a workspace method index is supplied
    (``go_helper_index``/``go_file_sources``), the scan ALSO follows call-hops
    into keeper/helper methods (FIX-3 class B) so oracle reads that live one or
    more hops below the value-moving function - e.g. nuva's
    ``GetNetAssetValue`` inside ``UnitPriceFraction`` reached from ``SwapIn`` -
    are surfaced. Intra-procedural behaviour for every language is unchanged.
    """
    fn_re = _vmf()._FN_RES.get(language)
    if fn_re is None:
        return []

    # Locate the function in source.
    fn_match = None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            fn_match = m
            break
    if fn_match is None:
        return []

    body, fn_line = _extract_fn_body(source, fn_match)

    # Early-exit: if the whole body is guarded, emit nothing. This preserves the
    # existing intra-procedural contract. Inter-procedural reads (Go) apply their
    # own path-scoped guard union below, so they are skipped here too when the
    # value-moving fn's own body already clamps/validates the price.
    if _is_guarded(body, language):
        return []

    oracle_pats = _LANG_ORACLE_READS.get(language, [])
    hypotheses: list[dict[str, Any]] = []
    seen_kinds: set[str] = set()
    # read_sites already emitted for this fn - used only to make the generic Go
    # "keeper price getter" idiom a fallback that does not double-emit a site a
    # specific idiom already covered.
    seen_sites: set[str] = set()

    for pat, read_kind, movability_reason in oracle_pats:
        m = pat.search(body)
        if not m:
            continue
        if read_kind in seen_kinds:
            continue

        # Compute line number relative to the file.
        # m.start() is offset within body; fn_match.start() is offset within source.
        abs_offset = fn_match.start() + m.start()
        read_line = _line_number(source, abs_offset)
        read_site = f"{file_rel}:{read_line}"

        # Generic Go getter is a per-site fallback: skip when a specific idiom
        # already emitted a row at this exact read site.
        if read_kind == _GO_GENERIC_GETTER_KIND and read_site in seen_sites:
            continue

        seen_kinds.add(read_kind)
        seen_sites.add(read_site)
        read_snippet = source.splitlines()[read_line - 1].strip() if read_line <= len(source.splitlines()) else ""

        # Determine sub_class for this hypothesis.
        if language == "sol":
            sub_class = _sol_sub_class(body, read_kind)
        else:
            sub_class = "movable-spot"

        hypotheses.append({
            "workspace":         ws_abs,
            "file":              file_rel,
            "function":          fn_name,
            "language":          language,
            "read_site":         read_site,
            "read_snippet":      read_snippet,
            "read_kind":         read_kind,
            "movability_reason": movability_reason,
            "value_loss_path":   _VALUE_LOSS_NOTES.get(read_kind, "price drives value-moving arithmetic"),
            "attack_class":      "oracle-price-manipulation",
            "sub_class":         sub_class,
            "source":            "ORL",
            "verdict":           "needs-fuzz",
        })

    # Inter-procedural Go extension (FIX-3 class B): follow call-hops from this
    # value-moving function into keeper/helper methods and scan those bodies.
    if language == "go" and go_helper_index is not None and go_file_sources is not None:
        interproc = _detect_go_interproc_reads(
            vmf_name=fn_name,
            vmf_body=body,
            method_index=go_helper_index,
            file_sources=go_file_sources,
            seen_kinds=seen_kinds,
            seen_sites=seen_sites,
            max_hops=go_max_hops,
        )
        for h in interproc:
            h["workspace"] = ws_abs
            hypotheses.append(h)

    return hypotheses


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------

def run_orl(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> int:
    """Run ORL over all value-moving functions in ``workspace``.

    Returns rc=0 on success, rc=1 on error.
    """
    ws = Path(workspace).resolve()
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)

    # Resolve value_moving_functions.json path.
    vmf_path = Path(vmf_json_path) if vmf_json_path else audit_dir / "value_moving_functions.json"

    # Re-generate VMF JSON if needed.
    if regen_vmf or not vmf_path.exists():
        vmf_mod = _vmf()
        rc = vmf_mod.run(str(ws), out_path=str(vmf_path))
        if rc != 0:
            print(f"ERROR: value-moving-functions.py failed (rc={rc})", file=sys.stderr)
            return 1

    if not vmf_path.exists():
        print(f"ERROR: {vmf_path} does not exist and could not be generated", file=sys.stderr)
        return 1

    with vmf_path.open() as f:
        vmf_data = json.load(f)

    functions: list[dict[str, Any]] = vmf_data.get("functions", [])
    if not functions:
        print(f"INFO: no value-moving functions found in {vmf_path}", file=sys.stderr)

    out = Path(out_path) if out_path else audit_dir / "oracle_reachability_hypotheses.jsonl"

    # Languages actually present in the value-moving-function set (for the
    # move/cairo fail-loud blind-marker below).
    langs_present: set[str] = {
        fn_rec.get("language", "")
        for fn_rec in functions
        if fn_rec.get("language")
    }

    # Build the Go workspace method index once (inter-procedural FIX-3 class B).
    go_helper_index: dict[str, list[dict[str, Any]]] | None = None
    go_file_sources: dict[str, str] | None = None
    if "go" in langs_present:
        go_helper_index, go_file_sources = _build_go_helper_index(ws)

    total_hypotheses = 0
    lang_counts: dict[str, int] = {}
    with out.open("w") as fh:
        for fn_rec in functions:
            rel_path = fn_rec.get("file", "")
            if is_oos(rel_path):
                continue
            lang = fn_rec.get("language", "")
            fn_name = fn_rec.get("function", "")
            if not fn_name or not lang:
                continue

            abs_path = ws / rel_path
            if not abs_path.exists():
                continue

            try:
                source = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            hypotheses = detect_oracle_reads(
                source=source,
                language=lang,
                fn_name=fn_name,
                file_rel=rel_path,
                ws_abs=str(ws),
                go_helper_index=go_helper_index if lang == "go" else None,
                go_file_sources=go_file_sources if lang == "go" else None,
            )
            for h in hypotheses:
                fh.write(json.dumps(h) + "\n")
                total_hypotheses += 1
                lang_counts[h.get("language", lang)] = (
                    lang_counts.get(h.get("language", lang), 0) + 1
                )

        # FAIL-LOUD blind markers (rule 3): Move / Cairo are PRESENT in the
        # workspace but ORL ships NO oracle-read idioms for them yet. Emitting a
        # declared-not-implemented marker prevents a silent 0-rows from reading
        # as a clean "no oracle reads" pass. We deliberately do NOT ship
        # unconfirmable Move/Cairo idioms (no fleet witness).
        for blind_lang in ("move", "cairo"):
            if blind_lang in langs_present and not _LANG_ORACLE_READS.get(blind_lang):
                marker = {
                    "workspace":         str(ws),
                    "file":              "",
                    "function":          "",
                    "language":          blind_lang,
                    "read_site":         "",
                    "read_snippet":      "",
                    "read_kind":         f"{blind_lang}-oracle-reads-not-implemented",
                    "movability_reason": (
                        f"ORL has NO oracle-read idioms for '{blind_lang}' "
                        f"(declared-not-implemented / no-fleet-witness); "
                        f"a 0-row {blind_lang} result is BLIND, not a clean pass"
                    ),
                    "value_loss_path":   "n/a - arm not implemented for this language",
                    "attack_class":      "oracle-price-manipulation",
                    "sub_class":         "movable-spot",
                    "source":            "ORL",
                    "verdict":           "blind",
                    "status":            "blind",
                    "degrade_reason":    (
                        f"{blind_lang}: oracle-read idioms declared-not-implemented "
                        f"(no fleet witness) - fail-loud marker, not a finding"
                    ),
                }
                fh.write(json.dumps(marker) + "\n")

    ts = datetime.now(timezone.utc).isoformat()
    lang_summary = ", ".join(f"{k}={v}" for k, v in sorted(lang_counts.items())) or "none"
    print(
        f"ORL complete: {total_hypotheses} oracle-reachability hypotheses "
        f"[{lang_summary}] -> {out}  [{ts}]"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ORL: detect attacker-movable oracle reads consumed on value-loss paths."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override .jsonl output path")
    parser.add_argument("--vmf-json", default=None, help="Override value_moving_functions.json path")
    parser.add_argument("--regen-vmf", action="store_true", help="Re-run VMF even if JSON exists")
    args = parser.parse_args(argv)

    return run_orl(
        workspace=args.workspace,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        regen_vmf=args.regen_vmf,
    )


if __name__ == "__main__":
    sys.exit(_main())
