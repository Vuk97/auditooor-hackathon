"""
go-oracle-price-threshold-stale-fire32.py

Fire32 Go lift for oracle-price-manipulation.

Flags Go oracle consumers that read a price, tick, TWAP, or index value and
then use it in margin, liquidation, settlement, borrow, collateral, or payout
logic after checking only one guard family: deviation, freshness, or source
identity. The miss class is partial oracle validation: a current-looking price
can still be wrong-source, a trusted-source price can still be stale, and a
within-deviation price can still be stale or sourced from the wrong feed.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire31_20260605/post_priorities_go.md
  - detectors/rust_wave1/rust_oracle_twap_deviation_fire31.py
  - reference/patterns.dsl/oracle-staleness-check-delegated-missing-revert.yaml
  - reference/patterns.dsl.zellic_k2_mined/cached-oracle-prices-ignore-per-asset-freshness-limits.yaml

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-oracle-price-threshold-stale-fire32"

_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'' )

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"twap|TWAP|tick|sourceID|SourceID|sourceId|feedID|FeedID)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*(?:Get|Read|Fetch|Load|Latest|Index|Twap|TWAP|Spot|"
    r"Market)[A-Za-z0-9_]*(?:Price|Prices|Tick|Ticks|Twap|TWAP|Index)?"
    r"\s*\(|"
    r"\b(?:Get|Read|Fetch|Load|Latest|Index|Twap|TWAP|Spot|Market)"
    r"[A-Za-z0-9_]*(?:Price|Prices|Tick|Ticks|Twap|TWAP|Index)\s*\(|"
    r"\b(?:price|oraclePrice|marketPrice|markPrice|spotPrice|indexPrice|"
    r"twapPrice|lastPrice|cachedPrice|tick|twap|index)\s*(?::=|=)"
    r")"
)

_VALUE_MOVEMENT_NAME_RE = re.compile(
    r"(liquidat|settle|settlement|margin|collateral|borrow|repay|debt|"
    r"health|position|notional|funding|payout|seize|mint|redeem|deposit|"
    r"withdraw|vault|loan)",
    re.IGNORECASE,
)

_VALUE_MOVEMENT_BODY_RE = re.compile(
    r"(?is)("
    r"\.(?:Liquidate|Settle|SettleFunding|OpenPosition|UpdateMargin|"
    r"Borrow|Repay|Mint|Redeem|Deposit|Withdraw|Transfer|Payout|Seize)"
    r"\s*\(|"
    r"\b(?:liquidation|settlement|margin|collateral|debt|borrow|repay|"
    r"healthFactor|health_factor|notional|position|funding|payout|seized|"
    r"vault|loan|equity)\b"
    r"[\s\S]{0,260}(?:[+\-*/%]=|:=|=|\*)|"
    r"\b(?:price|oraclePrice|marketPrice|markPrice|spotPrice|indexPrice|"
    r"twapPrice|lastPrice|cachedPrice|tick|twap|index)\b"
    r"[\s\S]{0,160}(?:[*/+\-]|\.Mul|\.Quo|\.Sub|\.Add)"
    r")"
)

_PURE_HELPER_NAME_RE = re.compile(
    r"^(?:Get|Read|Fetch|Load|Compute|Calculate|Calc)[A-Za-z0-9_]*"
    r"(?:Age|Staleness|Freshness|Delay|Lag|Timestamp|Source|SourceID|"
    r"Deviation|PriceDelta)$",
    re.IGNORECASE,
)

_FRESHNESS_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Fresh|Freshness|Stale|Staleness|Heartbeat|Age|Timestamp)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:fresh|stale|staleness|heartbeat|maxAge|max_age|maxStaleness|"
    r"max_staleness|maxDelay|ttl|TTL|updatedAt|UpdatedAt|timestamp|"
    r"Timestamp|publishTime|PublishTime|lastUpdate|LastUpdate|BlockTime)"
    r"[^{}]{0,900}\{[^{}]{0,520}"
    r"(?:return|panic|Err|error)|"
    r"(?:BlockTime\s*\(\s*\)|time\.Now\s*\(\s*\)|now|blockTime)"
    r"[^{}\n;]{0,260}(?:Sub|After|Before|>|<|>=|<=)"
    r"[^{}\n;]{0,260}"
    r"(?:UpdatedAt|updatedAt|Timestamp|timestamp|PublishTime|publishTime|"
    r"LastUpdate|lastUpdate|maxAge|maxStaleness|heartbeat|ttl)|"
    r"(?:UpdatedAt|updatedAt|Timestamp|timestamp|PublishTime|publishTime|"
    r"LastUpdate|lastUpdate)"
    r"[^{}\n;]{0,260}(?:Add|After|Before|>|<|>=|<=)"
    r"[^{}\n;]{0,260}"
    r"(?:BlockTime|time\.Now|now|blockTime|maxAge|maxStaleness|heartbeat|ttl)"
    r")"
)

_DEVIATION_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Deviation|Tolerance|PriceBand|Bounds|Sanity|Threshold|Twap|TWAP)"
    r"\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:deviation|maxDeviation|max_deviation|maxChange|max_change|"
    r"threshold|tolerance|absDiff|abs_diff|withinTolerance|priceBand|"
    r"price_band|bounds|sanity|bps|Bps|basisPoints|twapWindow|"
    r"TWAPWindow|twapDeviation|TWAPDeviation)"
    r"[^{}]{0,900}\{[^{}]{0,520}"
    r"(?:return|panic|Err|error)|"
    r"\b(?:deviation|priceDelta|delta|absDiff|abs_diff)\s*(?::=|=)"
    r"[^{}\n;]{0,260}"
    r"(?:price|Price|tick|Tick|twap|TWAP)"
    r")"
)

_SOURCE_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Source|Provider|Feed|Oracle|MarketID)\s*\(|"
    r"\b(?:IsTrustedSource|TrustedSource|AllowedSource|SourceAllowed)"
    r"\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:sourceID|SourceID|sourceId|SourceId|feedID|FeedID|feedId|"
    r"provider|Provider|oracleID|OracleID|oracleId|marketID|MarketID)"
    r"[^{}]{0,260}(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
    r"[^{}]{0,900}\{[^{}]{0,520}"
    r"(?:return|panic|Err|error)"
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank, src)
    return re.sub(r"/\*.*?\*/", _blank, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    return _STRING_RE.sub(_blank, _strip_comments(src))


def _guard_families(body_text: str) -> set[str]:
    families: set[str] = set()
    if _FRESHNESS_GUARD_RE.search(body_text):
        families.add("freshness")
    if _DEVIATION_GUARD_RE.search(body_text):
        families.add("deviation")
    if _SOURCE_GUARD_RE.search(body_text):
        families.add("source")
    return families


def _has_oracle_value_source(fn_text: str, body_text: str) -> bool:
    return bool(
        _ORACLE_CONTEXT_RE.search(fn_text)
        and (_ORACLE_READ_RE.search(body_text) or _ORACLE_CONTEXT_RE.search(body_text))
    )


def _has_value_moving_sink(name: str, body_text: str) -> bool:
    return bool(
        _VALUE_MOVEMENT_NAME_RE.search(name)
        or _VALUE_MOVEMENT_BODY_RE.search(body_text)
    )


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _has_oracle_value_source(fn_text, body_text):
        return None
    if not _has_value_moving_sink(name, body_text):
        return None

    families = _guard_families(body_text)
    if len(families) != 1:
        return None

    only = next(iter(families))
    missing = ", ".join(sorted({"deviation", "freshness", "source"} - families))
    return f"checks only {only} guard before value-moving oracle use; missing {missing}"


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue

        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = _strip_comments(engine.text(fn))
        body_text = _strip_comments_and_strings(engine.text(body))
        reason = _candidate_reason(name, fn_text, body_text)
        if reason is None:
            continue

        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": engine.text(fn).splitlines()[0][:160],
                "message": (
                    f"`{name}` accepts an oracle price, tick, TWAP, or index "
                    f"value with partial validation: {reason}. Require "
                    f"freshness, trusted-source binding, and deviation or "
                    f"sanity validation before using oracle values in margin, "
                    f"liquidation, or settlement logic. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
