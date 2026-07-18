#!/usr/bin/env python3
"""mev-ordering-lane.py  (MOL) - MEV / Ordering-Sensitive Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
MOL scans the function body for ORDERING-SENSITIVE PRICE READS: a mutable pool
price / reserve / spot-price read whose value can change between the block the
user quotes and the block their transaction executes. A same-block attacker
(sandwich / front-run) can manipulate this mutable state to extract value.

The function is classified PROTECTED or UNPROTECTED:

  PROTECTED (emit 0 hypotheses) when ANY of the following fire in the same
  function scope as the ordering-sensitive read:
  - A checked slippage bound: minAmountOut / minOut / minShares / minLP /
    minTokens / min_amount_out / min_out / min_shares / slippageOut / minReturn
    / minReceived / slippageTolerance / amountOutMin / minExpectedAmount
    used in a comparison or require/assert/revert.
  - A deadline / expiry check: deadline / expiry / expire / validUntil /
    validDeadline / expirationTime keyword (deadline as param or compared).
  - A commit-reveal guard: commit / reveal / nonce keyword in the function name
    or body that indicates a two-phase submission.
  - A TWAP-settled price: TWAP / twap / timeWeightedAveragePrice keyword
    (the price is averaged over time, not a spot read).

  UNPROTECTED: the function reads mutable pool/price state AND none of the
  above protection patterns fire. MOL emits one hypothesis per
  (function, sensitive_read_site) pair, verdict="needs-fuzz".

WHAT IS ORDERING-SENSITIVE
===========================
A price/state read is ordering-sensitive when it reads a value that a
same-block adversary can move by inserting a tx before the victim:

  Solidity (AMM / DEX / FCFS):
  - getReserves() / reserves / reserve0 / reserve1  (Uniswap-V2-style AMM)
  - slot0() / sqrtPriceX96 / currentTick / tick     (Uniswap-V3 current state)
  - price()  / getPrice() / latestPrice()            (spot oracle with no TWAP)
  - poolPrice / spotPrice / currentPrice             (inline pool price access)
  - amountOut = getAmountOut(...) / calcAmountOut    (AMM output calc from reserves)
  - getBestPrice / getQuote / quote                  (live quote functions)
  - balanceOf(address(this))  used as the denominator/numerator in a ratio
    (reserve-style spot calc vulnerable to donation)

  Go / Cosmos (exchange / margin):
  - GetMarkPrice / GetSpotPrice / GetExecutionPrice  (exchange mark price)
  - GetBestAsk / GetBestBid / GetMidPrice / GetLevel2Price
  - executeAtMarketPrice / marketOrder / fillAtMark
  - GetLiquidationPrice / GetMidPointPrice

  Rust / CosmWasm (DEX / swap execute):
  - compute_swap / get_swap_amount / compute_offer_amount / compute_ask_amount
  - pool.get_price() / reserve.price() / spot_price()
  - calculate_price / get_current_price / fetch_price

WHAT IS NOT ORDERING-SENSITIVE (do NOT flag)
==============================================
  - Fixed-tick / fixed-price order book: the execution price is committed at
    offer creation time, stored in the offer record (tick / price field), and
    the settlement merely reads the stored value.
    Indicators: tick / tickPrice / offer.tick / offer.price / tickToPrice()
    WITHOUT any live getReserves() / slot0() / getAmountOut() call.
  - Pure fixed-rate repayments (fixed interest, no market price read).
  - Governance votes and admin operations (no AMM price dependency).

WHY THE 6 EXISTING LANES MISS THIS
====================================
VCIS: checks value-conservation (sum-in = sum-out), not path ORDER.
SADL: checks self-dealing, not inter-tx ordering.
CRC:  checks callback reentrancy (intra-tx), not inter-tx ordering.
SIDL: checks share inflation (deposit/mint ratio), not spot-price timing.
ORL:  checks ORACLE staleness (stale at read time), not sandwich timing.
RDL:  checks rounding direction, not adversarial reordering.
None models a SAME-BLOCK adversary that manipulates state between tx A and tx B.

NO FALSE-GREEN RULE
===================
MOL NEVER auto-confirms a finding. Every emitted record carries
verdict="needs-fuzz". An attacker-controlled state-manipulation invariant
spec is emitted as the fuzzer oracle hint.

LANGUAGES SUPPORTED
===================
Solidity, Go/Cosmos, Rust

OUTPUT FILES
============
1. <ws>/.auditooor/mev_ordering_hypotheses.jsonl  - hypothesis records

HYPOTHESIS SCHEMA
=================
{
  "workspace":            "<abs-path>",
  "file":                 "<rel-path>",
  "function":             "<fn-name>",
  "language":             "sol|go|rs",
  "sensitive_read_site":  "<rel-path>:<line>",
  "sensitive_read_snippet": "<matched source line>",
  "read_kind":            "<category>",
  "protection_check":     "UNPROTECTED",
  "protection_reason":    "<why no protection found>",
  "attack_class":         "sandwich-front-run-ordering",
  "source":               "MOL",
  "verdict":              "needs-fuzz",
  "fuzz_oracle_hint":     "<invariant spec for fuzzer>"
}

CLI
===
  python3 tools/mev-ordering-lane.py <workspace> [--out <path>]
  --vmf-json:   override value_moving_functions.json path
  --regen-vmf:  re-run value-moving-functions.py even if JSON exists

Returns rc=0 on success (even 0 hypotheses), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# OOS guard.
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
_VMF_MOD_NAME = "value_moving_functions_mol_import"
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
# ORDERING-SENSITIVE READ PATTERNS (per language).
#
# Each entry: (pattern, read_kind, note_on_why_sensitive)
# Applied to the extracted function-body text.
# ---------------------------------------------------------------------------

# Solidity - AMM / DEX spot price reads.
_SOL_SENSITIVE: list[tuple[re.Pattern, str, str]] = [
    # Uniswap V2 getReserves() - raw spot reserves
    (
        re.compile(r"\bgetReserves\s*\(", re.I),
        "uniswap-v2-getReserves",
        "raw AMM spot reserves readable/movable by a sandwich tx in the same block",
    ),
    # Uniswap V3 slot0() - current sqrtPriceX96 / tick
    (
        re.compile(r"\bslot0\s*\(", re.I),
        "uniswap-v3-slot0",
        "current UniswapV3 tick/sqrtPriceX96 - manipulable via same-block large swap",
    ),
    # getAmountOut / calcAmountOut - AMM output based on live reserves
    (
        re.compile(r"\bgetAmountOut\s*\(|\bcalcAmountOut\s*\(|\bcalculateAmountOut\s*\(", re.I),
        "amm-getAmountOut",
        "AMM output computed from live reserves - result changes if reserves are manipulated first",
    ),
    # getAmountsOut / getAmountsIn (router-level, reads reserves internally)
    (
        re.compile(r"\bgetAmountsOut\s*\(|\bgetAmountsIn\s*\(", re.I),
        "amm-router-getAmountsOut",
        "router-level amounts derived from live reserves - sandwichable",
    ),
    # getBestPrice / getQuote / quote - live quote reads
    (
        re.compile(r"\bgetBestPrice\s*\(|\bgetQuote\s*\(|\b\bquote\s*\(", re.I),
        "live-quote",
        "live price quote from AMM or orderbook - may change between quote and execution",
    ),
    # spotPrice / currentPrice / poolPrice accessed as a storage/state read
    (
        re.compile(r"\b(?:spot|current|pool|market)Price\b", re.I),
        "spot-price-read",
        "mutable spot/current/pool/market price field - front-runner can move this state",
    ),
    # sqrtPriceX96 as a direct read (Uniswap V3 math path)
    (
        re.compile(r"\bsqrtPriceX96\b"),
        "uniswap-v3-sqrtPriceX96",
        "UniswapV3 current sqrtPriceX96 spot read - manipulable by a same-block large swap",
    ),
    # balanceOf(address(this)) used as a reserve proxy
    (
        re.compile(r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", re.I),
        "balanceof-this-reserve",
        "balanceOf(address(this)) as reserve denominator - donation or flash-mint can manipulate",
    ),
]

# Go / Cosmos - exchange market price reads.
_GO_SENSITIVE: list[tuple[re.Pattern, str, str]] = [
    # GetMarkPrice / GetSpotPrice / GetExecutionPrice
    (
        re.compile(r"\bGetMarkPrice\s*\(|\bGetSpotPrice\s*\(|\bGetExecutionPrice\s*\(", re.I),
        "cosmos-exchange-price",
        "exchange mark/spot/execution price from state - manipulable by prior tx in same block",
    ),
    # GetBestAsk / GetBestBid / GetMidPrice
    (
        re.compile(r"\bGetBest(?:Ask|Bid)\s*\(|\bGetMidPrice\s*\(|\bGetMidPointPrice\s*\(", re.I),
        "cosmos-orderbook-best-price",
        "best ask/bid/mid price from live orderbook - can change between query and settlement",
    ),
    # executeAtMarketPrice / fillAtMark / marketOrder
    (
        re.compile(r"\bexecuteAtMarketPrice\s*\(|\bfillAtMark\s*\(|\bmarketOrder\s*\(", re.I),
        "cosmos-market-order",
        "market order settles at live mark price - adversarial ordering can move mark before settlement",
    ),
    # GetLevel2Price / GetAggregatedPrice
    (
        re.compile(r"\bGetLevel2Price\s*\(|\bGetAggregatedPrice\s*\(", re.I),
        "cosmos-aggregated-price",
        "aggregated/level2 price from exchange state - live and reorderable",
    ),
    # GetLiquidationPrice at spot (no staleness concern, but ordering-sensitive)
    (
        re.compile(r"\bGetLiquidationPrice\s*\(", re.I),
        "cosmos-liquidation-price",
        "liquidation price threshold uses spot price - reorderable if spot manipulated first",
    ),
]

# Rust - DEX / swap compute functions.
_RS_SENSITIVE: list[tuple[re.Pattern, str, str]] = [
    # compute_swap / compute_offer_amount / compute_ask_amount
    (
        re.compile(r"\bcompute_swap\s*\(|\bcompute_offer_amount\s*\(|\bcompute_ask_amount\s*\(", re.I),
        "rs-amm-compute-swap",
        "AMM swap amount computed from pool state at execution time - manipulable by prior tx",
    ),
    # spot_price / get_current_price / calculate_price
    (
        re.compile(r"\bspot_price\s*\(|\bcalculate_price\s*\(|\bget_current_price\s*\(|\bfetch_price\s*\(", re.I),
        "rs-spot-price",
        "live spot/current price computation from pool state - ordering-sensitive",
    ),
    # pool.get_price() / reserve.price()
    (
        re.compile(r"\b(?:pool|reserve|state)\s*\.\s*(?:get_)?price\s*\(", re.I),
        "rs-pool-price",
        "pool/reserve price read at execution time - a prior tx can move the pool state",
    ),
    # get_swap_amount
    (
        re.compile(r"\bget_swap_amount\s*\(", re.I),
        "rs-get-swap-amount",
        "swap amount derived from live pool state - sandwichable",
    ),
]

_LANG_SENSITIVE: dict[str, list[tuple[re.Pattern, str, str]]] = {
    "sol": _SOL_SENSITIVE,
    "go": _GO_SENSITIVE,
    "rs": _RS_SENSITIVE,
    "move": [],
    "cairo": [],
}


# ---------------------------------------------------------------------------
# FIXED-PRICE INDICATORS: if these fire, the function settles at a STORED
# (commit-time) price, not a live spot price. Skip even if sensitive read
# patterns are absent (belt-and-suspenders false-positive guard).
# ---------------------------------------------------------------------------
_FIXED_PRICE_INDICATORS: list[re.Pattern] = [
    # Fixed-tick orderbook: offer.tick / tickToPrice / priceToTick
    re.compile(r"\boffer\s*\.\s*tick\b"),
    re.compile(r"\btickToPrice\s*\("),
    re.compile(r"\bpriceToTick\s*\("),
    # Named field on an offer struct used as the settlement price
    re.compile(r"\boffer\s*\.\s*price\b"),
    re.compile(r"\bofferPrice\b"),
    # Fixed-rate terms (not market-linked)
    re.compile(r"\bfixedRate\b|\bfixed_rate\b|\binterestRate\b|\binterest_rate\b"),
]


# ---------------------------------------------------------------------------
# PROTECTION PATTERNS (per language).
# If ANY fires in the same function body, the fn is PROTECTED -> 0 hypotheses.
# ---------------------------------------------------------------------------

_SOL_PROTECTIONS: list[re.Pattern] = [
    # Slippage bounds (checked minOut / minAmountOut / etc.)
    re.compile(r"\bminAmountOut\b", re.I),
    re.compile(r"\bminOut\b", re.I),
    re.compile(r"\bminShares\b", re.I),
    re.compile(r"\bminLP\b", re.I),
    re.compile(r"\bminTokens\b", re.I),
    re.compile(r"\bmin_amount_out\b", re.I),
    re.compile(r"\bmin_out\b", re.I),
    re.compile(r"\bmin_shares\b", re.I),
    re.compile(r"\bminReturn\b", re.I),
    re.compile(r"\bminReceived\b", re.I),
    re.compile(r"\bamountOutMin\b", re.I),
    re.compile(r"\bminExpectedAmount\b", re.I),
    re.compile(r"\bslippageTolerance\b", re.I),
    re.compile(r"\bSlippageOut\b", re.I),
    re.compile(r"\bSlippageIn\b", re.I),
    # Deadline / expiry check
    re.compile(r"\bdeadline\b", re.I),
    re.compile(r"\bexpir(?:y|e|ation)\b", re.I),
    re.compile(r"\bvalidUntil\b", re.I),
    re.compile(r"\bexpirationTime\b", re.I),
    # TWAP: time-averaged price is not reorderable in a single block
    re.compile(r"\bTWAP\b", re.I),
    re.compile(r"\btwapPrice\b", re.I),
    re.compile(r"\btwap_price\b", re.I),
    re.compile(r"\bsecondsAgo\b"),
    re.compile(r"\bconsult\s*\(", re.I),
    # Commit-reveal guard
    re.compile(r"\bcommit\b", re.I),
    re.compile(r"\breveal\b", re.I),
]

_GO_PROTECTIONS: list[re.Pattern] = [
    # Slippage: minOut / minAmount / slippageTolerance
    re.compile(r"\bminAmount\b", re.I),
    re.compile(r"\bminOut\b", re.I),
    re.compile(r"\bslippageTolerance\b", re.I),
    re.compile(r"\bSlippageProtection\b", re.I),
    re.compile(r"\bMinAmountOut\b", re.I),
    # Deadline
    re.compile(r"\bDeadline\b"),
    re.compile(r"\bExpiry\b"),
    re.compile(r"\bValidUntil\b", re.I),
    # TWAP
    re.compile(r"\bTWAP\b", re.I),
    re.compile(r"\bTwapPrice\b"),
]

_RS_PROTECTIONS: list[re.Pattern] = [
    # Slippage
    re.compile(r"\bmin_amount_out\b", re.I),
    re.compile(r"\bmin_out\b", re.I),
    re.compile(r"\bslippage\b", re.I),
    re.compile(r"\bmin_receive\b", re.I),
    re.compile(r"\bminimum_receive\b", re.I),
    # Deadline
    re.compile(r"\bdeadline\b", re.I),
    re.compile(r"\bexpiry\b", re.I),
    # TWAP
    re.compile(r"\btwap\b", re.I),
]

_LANG_PROTECTIONS: dict[str, list[re.Pattern]] = {
    "sol": _SOL_PROTECTIONS,
    "go": _GO_PROTECTIONS,
    "rs": _RS_PROTECTIONS,
    "move": [],
    "cairo": [],
}


# ---------------------------------------------------------------------------
# Fuzzer oracle hint per read kind.
# ---------------------------------------------------------------------------
_FUZZ_ORACLE_HINTS: dict[str, str] = {
    "uniswap-v2-getReserves":     "INV: amountOut(sandwich_state) <= amountOut(pre_state); manipulate reserves via flash-swap, call victim, assert outcome deviation",
    "uniswap-v3-slot0":           "INV: amountOut(tick_moved) <= amountOut(fair_tick); move sqrtPriceX96 via large swap, call victim, assert deviation",
    "amm-getAmountOut":           "INV: getAmountOut result must not decrease after honest deposit; test with manipulated reserves",
    "amm-router-getAmountsOut":   "INV: getAmountsOut result with manipulated pool state < result with honest state; assert deviation bound",
    "live-quote":                 "INV: quote at T must equal execution price at T+1 within tolerance; test ordering attack violates this",
    "spot-price-read":            "INV: price at query time equals price at execution time; sandwich moves price between the two",
    "uniswap-v3-sqrtPriceX96":    "INV: sqrtPriceX96-derived output not worse than TWAP output by more than slippage bound",
    "balanceof-this-reserve":     "INV: balanceOf(this) before tx must equal balanceOf(this) after identical deposit; flash donation breaks this",
    "cosmos-exchange-price":      "INV: mark price at order submission equals mark price at settlement; test with front-run price move",
    "cosmos-orderbook-best-price":"INV: best ask/bid at submission <= best ask/bid at fill; test with adversarial order insertion",
    "cosmos-market-order":        "INV: market order fill price within x% of mark at submission time; test adversarial tx ordering",
    "cosmos-aggregated-price":    "INV: aggregated price at query time not deviated by adversarial single-source update",
    "cosmos-liquidation-price":   "INV: liquidation threshold not crossable by temporary price manipulation within one block",
    "rs-amm-compute-swap":        "INV: compute_swap output with honest pool state >= compute_swap output with adversarial state; assert lower bound",
    "rs-spot-price":              "INV: spot price at compute time equals price at settlement; test with interleaved state-moving tx",
    "rs-pool-price":              "INV: pool price read in execute matches pool price at user intent time; test sandwich",
    "rs-get-swap-amount":         "INV: swap amount with manipulated pool state < swap amount with honest state; assert deviation",
}


# ---------------------------------------------------------------------------
# Function body extractor (identical pattern to ORL / RDL).
# ---------------------------------------------------------------------------

def _extract_fn_body(source: str, fn_match: re.Match) -> tuple[str, int]:
    start = fn_match.start()
    start_line = source[:start].count("\n") + 1
    brace_pos = source.find("{", fn_match.end())
    if brace_pos == -1:
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


def _line_number(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


# ---------------------------------------------------------------------------
# Protection and fixed-price checks.
# ---------------------------------------------------------------------------

def _is_protected(body: str, lang: str) -> bool:
    """Return True if any protection pattern fires in ``body``."""
    for pat in _LANG_PROTECTIONS.get(lang, []):
        if pat.search(body):
            return True
    return False


def _is_fixed_price(body: str) -> bool:
    """Return True if the function settles at a stored (committed) price."""
    for pat in _FIXED_PRICE_INDICATORS:
        if pat.search(body):
            return True
    return False


# ---------------------------------------------------------------------------
# Core per-function detection.
# ---------------------------------------------------------------------------

def detect_ordering_sensitive(
    source: str,
    language: str,
    fn_name: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/mol_fixture_ws",
) -> list[dict[str, Any]]:
    """Detect ordering-sensitive unprotected reads in a single function.

    Returns a list of hypothesis dicts (may be empty).
    Primary unit-testable entry point.

    ``source`` must contain the full function definition (or enough surrounding
    context for the function regex to locate it).
    """
    fn_re = _vmf()._FN_RES.get(language)
    if fn_re is None:
        return []

    fn_match = None
    for m in fn_re.finditer(source):
        if m.group(1) == fn_name:
            fn_match = m
            break
    if fn_match is None:
        return []

    body, fn_line = _extract_fn_body(source, fn_match)

    # Gate 1: fixed-price functions are not ordering-sensitive.
    if _is_fixed_price(body):
        return []

    # Gate 2: protected functions (slippage bound / deadline / TWAP present).
    if _is_protected(body, language):
        return []

    sensitive_pats = _LANG_SENSITIVE.get(language, [])
    hypotheses: list[dict[str, Any]] = []
    seen_kinds: set[str] = set()

    for pat, read_kind, sensitivity_reason in sensitive_pats:
        m = pat.search(body)
        if not m:
            continue
        if read_kind in seen_kinds:
            continue
        seen_kinds.add(read_kind)

        abs_offset = fn_match.start() + m.start()
        read_line = _line_number(source, abs_offset)
        lines = source.splitlines()
        read_snippet = lines[read_line - 1].strip() if read_line <= len(lines) else ""

        hypotheses.append({
            "workspace":              ws_abs,
            "file":                   file_rel,
            "function":               fn_name,
            "language":               language,
            "sensitive_read_site":    f"{file_rel}:{read_line}",
            "sensitive_read_snippet": read_snippet,
            "read_kind":              read_kind,
            "sensitivity_reason":     sensitivity_reason,
            "protection_check":       "UNPROTECTED",
            "protection_reason":      (
                "no minAmountOut/minOut/minShares slippage bound, "
                "no deadline/expiry check, "
                "no TWAP, no commit-reveal found in function scope"
            ),
            "attack_class":           "sandwich-front-run-ordering",
            "source":                 "MOL",
            "verdict":                "needs-fuzz",
            "fuzz_oracle_hint":       _FUZZ_ORACLE_HINTS.get(
                read_kind,
                "INV: output with adversarial state manipulation < output with honest state",
            ),
        })

    return hypotheses


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------

def run_mol(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> int:
    """Run MOL over all value-moving functions in ``workspace``.

    Returns rc=0 on success, rc=1 on error.
    """
    ws = Path(workspace).resolve()
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)

    vmf_path = Path(vmf_json_path) if vmf_json_path else audit_dir / "value_moving_functions.json"

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

    out = Path(out_path) if out_path else audit_dir / "mev_ordering_hypotheses.jsonl"

    total_hypotheses = 0
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

            hypotheses = detect_ordering_sensitive(
                source=source,
                language=lang,
                fn_name=fn_name,
                file_rel=rel_path,
                ws_abs=str(ws),
            )
            for h in hypotheses:
                fh.write(json.dumps(h) + "\n")
                total_hypotheses += 1

    ts = datetime.now(timezone.utc).isoformat()
    print(
        f"MOL complete: {total_hypotheses} ordering-sensitive hypotheses "
        f"-> {out}  [{ts}]"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MOL: detect ordering-sensitive unprotected value-moving fns (MEV/sandwich/front-run)."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override .jsonl output path")
    parser.add_argument("--vmf-json", default=None, help="Override value_moving_functions.json path")
    parser.add_argument("--regen-vmf", action="store_true", help="Re-run VMF even if JSON exists")
    args = parser.parse_args(argv)

    return run_mol(
        workspace=args.workspace,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        regen_vmf=args.regen_vmf,
    )


if __name__ == "__main__":
    sys.exit(_main())
