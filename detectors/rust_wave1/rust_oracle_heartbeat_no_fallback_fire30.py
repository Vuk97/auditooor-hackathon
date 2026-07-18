"""
rust_oracle_heartbeat_no_fallback_fire30.py

Rust Fire30 lift for oracle-price-manipulation.

Flags price readers that observe a heartbeat or stale-cache condition and
still accept a live or cached price before a safe last-good value, TWAP guard,
secondary oracle, shutdown path, or fail-closed rejection. This complements
Fire27, which catches age computed but never compared.

Rule 37 provenance:
- local miss: oracle-heartbeat-no-fallback-fire27-positive
- local miss: r94-loop-oracle-heartbeat-no-fallback-positive
- source refs:
  - reference/patterns.dsl.zellic_k2_mined/cached-oracle-prices-ignore-per-asset-freshness-limits.yaml
  - reference/patterns.dsl.zellic_k2_mined/stale-price-cache-bypasses-oracle-config-changes.yaml
  - reference/patterns.dsl.zellic_k2_mined/oracle-reconfiguration-wipes-price-change-circuit-breaker-state.yaml
- attack_class: oracle-price-manipulation

Detector hits are source-review candidates only. R40/R80 proof still requires
a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.rust_oracle_heartbeat_no_fallback_fire30"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(?i)(oracle|price|feed|round|answer|pyth|chainlink|twap|"
    r"lastpricedata|last_price|cached_price|collateral|debt|health|"
    r"ltv|liquidat|margin|notional)"
)

_STALE_CONTEXT_RE = re.compile(
    r"(?i)(heartbeat|max_heartbeat|max_age|max_staleness|max_delay|"
    r"staleness|freshness|ttl|stale_after|price_staleness_threshold|"
    r"cache_ttl|updated_at|publish_time|last_update|timestamp|cache_age)"
)

_STALE_IF_RE = re.compile(
    r"(?is)\bif\s+"
    r"(?P<cond>[^{}]{0,760}"
    r"(?:age|stale|elapsed|delay|heartbeat|updated_at|publish_time|"
    r"last_update|timestamp|cache_age|cached_age)"
    r"[^{}]{0,760}(?:>|>=|<|<=)[^{}]{0,760}"
    r"(?:heartbeat|max_heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after|freshness|price_staleness_threshold|cache_ttl)"
    r"[^{}]{0,260})\s*\{(?P<branch>[^{}]{0,1400})\}"
)

_PRICE_ACCEPT_RE = re.compile(
    r"(?is)("
    r"return\s+(?:Ok\s*\()?[^;{}]{0,240}"
    r"(?:sample\.price|round\.answer|round\.price|feed\.price|"
    r"price_data\.price|cached\.price|cached_price|last_price|"
    r"stored_price|saved_price|oracle_price|current_price|latest_price|"
    r"\bprice\b)"
    r"|Ok\s*\([^)]{0,240}"
    r"(?:sample\.price|round\.answer|round\.price|feed\.price|"
    r"price_data\.price|cached\.price|cached_price|last_price|"
    r"stored_price|saved_price|oracle_price|current_price|latest_price|"
    r"\bprice\b)"
    r"|(?:price|oracle_price|current_price|latest_price)\s*=\s*"
    r"(?:sample\.price|round\.answer|round\.price|feed\.price|"
    r"price_data\.price|cached\.price|cached_price|last_price)"
    r")"
)

_SAFE_ACTION_RE = re.compile(
    r"(?is)("
    r"return\s+(?:Err|None)\b|Err\s*\(|bail!\s*\(|panic!\s*\(|"
    r"StalePrice|InvalidPrice|reject|fail_closed|failclosed|"
    r"fallback|secondary|backup|last_good|last_valid|safe_price|"
    r"twap|time_weighted|moving_average|median_price|"
    r"pause_market|halt_market|shutdown|disable_asset|freeze_market|"
    r"circuit_breaker|mark_stale|mark_invalid"
    r")"
)

_CACHE_CONTEXT_RE = re.compile(
    r"(?i)(lastpricedata|cached|cache|last_price|stored_price|"
    r"saved_price|price_data)"
)

_CACHE_RETURN_RE = re.compile(
    r"(?is)return\s+(?:Ok\s*\()?[^;{}]{0,260}"
    r"(?:cached\.price|cached_price|price_data\.price|last_price|"
    r"last\.price|stored_price|saved_price|last_price_data\.price)"
)

_CACHE_FRESHNESS_RE = re.compile(
    r"(?i)(price_staleness_threshold|cache_ttl|global_max_age|"
    r"default_max_age|default_staleness|max_cache_age|ttl|staleness)"
)

_PER_ASSET_GUARD_RE = re.compile(
    r"(?i)("
    r"asset_config\s*\.\s*(?:max_age|max_staleness|heartbeat|enabled|"
    r"oracle_source|source|freshness)"
    r"|asset_cfg\s*\.\s*(?:max_age|max_staleness|heartbeat|enabled|"
    r"oracle_source|source|freshness)"
    r"|per_asset_(?:max_age|max_staleness|heartbeat|freshness)"
    r"|market_config\s*\.\s*(?:max_age|max_staleness|heartbeat|enabled)"
    r"|price_config\s*\.\s*(?:max_age|max_staleness|heartbeat|enabled)"
    r")"
)

_ASSET_CONFIG_RE = re.compile(
    r"(?i)(asset_config|asset_cfg|per_asset|market_config|price_config|"
    r"set_asset_enabled|set_custom_oracle|set_fallback_oracle|"
    r"update_reflector_contract)"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _has_oracle_context(name: str, body: str) -> bool:
    return bool(_ORACLE_CONTEXT_RE.search(name) or _ORACLE_CONTEXT_RE.search(body))


def _unsafe_stale_branch_acceptance(body: str) -> str | None:
    for match in _STALE_IF_RE.finditer(body):
        cond = match.group("cond")
        if _PER_ASSET_GUARD_RE.search(cond):
            continue
        if not (re.search(r"(?:>=|>)", cond) or re.search(r"(?i)\bstale\b", cond)):
            continue
        branch = match.group("branch")
        if _SAFE_ACTION_RE.search(branch):
            continue
        if not _PRICE_ACCEPT_RE.search(branch):
            continue
        return "stale heartbeat branch accepts a live or cached price"
    return None


def _cached_return_before_asset_guard(body: str) -> str | None:
    if not (_CACHE_CONTEXT_RE.search(body) and _ASSET_CONFIG_RE.search(body)):
        return None
    if not _STALE_CONTEXT_RE.search(body):
        return None

    for match in _CACHE_RETURN_RE.finditer(body):
        before = body[max(0, match.start() - 850) : match.start()]
        if not (_CACHE_CONTEXT_RE.search(before) and _CACHE_FRESHNESS_RE.search(before)):
            continue
        if _SAFE_ACTION_RE.search(before):
            continue
        if _PER_ASSET_GUARD_RE.search(before):
            continue

        after = body[match.end() :]
        if _PER_ASSET_GUARD_RE.search(after) or _ASSET_CONFIG_RE.search(after):
            return "cached price returns before per-asset freshness or config guards"
    return None


def _candidate_reason(name: str, body: str) -> str | None:
    if not _has_oracle_context(name, body):
        return None
    if not _STALE_CONTEXT_RE.search(body):
        return None
    return _unsafe_stale_branch_acceptance(body) or _cached_return_before_asset_guard(body)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        body = _strip_strings(body_text_nocomment(body_node, source))
        reason = _candidate_reason(name, body)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"Rust oracle heartbeat no fallback candidate in `{name}`: "
                    f"{reason}. Add fail-closed freshness validation, "
                    "safe last-good fallback, TWAP guard, secondary oracle, "
                    "or shutdown before returning or consuming the price. "
                    "attack_class=oracle-price-manipulation."
                ),
            }
        )

    return hits
