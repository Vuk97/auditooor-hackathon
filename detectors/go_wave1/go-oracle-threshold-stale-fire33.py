"""
go-oracle-threshold-stale-fire33.py

Fire33 Go lift for oracle-price-manipulation.

Flags Go oracle consumers that read a price, median, index, threshold, or
quote and then feed it into settlement, margin, liquidation, debt, reserve, or
funding state before any freshness or price-quality guard appears. This is the
missing-validation counterpart to Fire32's partial-validation detector.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire32_20260605/post_priorities_go.md
  - detectors/go_wave1/go-oracle-price-threshold-stale-fire32.py
  - detectors/go_wave1/test_fixtures/go-oracle-price-threshold-stale-fire32_positive.go
  - reference/patterns.dsl/oracle-staleness-not-checked.yaml

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-oracle-threshold-stale-fire33"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|thresholdPrice|threshold|thresholds|twap|TWAP|"
    r"quote|quotes|tick)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source|marketPrices|prices|indexer|thresholds|"
    r"thresholdFeed|threshold_feed)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|"
    r"Threshold|Twap|TWAP|Spot|Market)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP)?\s*\(|"
    r"\b(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|Threshold|"
    r"Twap|TWAP|Spot|Market)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP)\s*\(|"
    r"\b(?:price|quote|oraclePrice|marketPrice|markPrice|spotPrice|"
    r"indexPrice|medianPrice|thresholdPrice|twapPrice|lastPrice|"
    r"cachedPrice|median|index|threshold)\s*(?::=|=)"
    r")"
)

_STATE_SINK_RE = re.compile(
    r"(?is)("
    r"\.(?:Settle|SettleFunding|SettleLiquidation|Liquidate|"
    r"MarkLiquidated|OpenPosition|UpdateMargin|RepriceMargin|ApplyMargin|"
    r"UpdateReserve|SetReserve|SettleReserve|UpdateDebt|Borrow|Repay|"
    r"Seize|Payout|Mint|Redeem)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:settlement|settle|margin|liquidation|liquidat|reserve|"
    r"reserves|collateral|debt|borrow|repay|health|solvency|position|"
    r"funding|payout|seized|notional)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]\n]+\])?\s*(?:=|\+=|-=|\*=|/=)|"
    r"\.(?:Settlement|SettlementPrice|Margin|MaintenanceMargin|Reserve|"
    r"Reserves|Debt|Collateral|Health|HealthFactor|LiquidationPrice|"
    r"Funding|FundingRate|Payout|Seized)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]\n]+\])?\s*(?:=|\+=|-=|\*=|/=)"
    r")"
)

_SAFE_SINK_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|cache)",
    re.IGNORECASE,
)

_VALIDATION_CALL_RE = re.compile(
    r"(?is)\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
    r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Fresh|Freshness|Stale|"
    r"Staleness|Heartbeat|Age|Timestamp|PublishTime|UpdatedAt|"
    r"Confidence|Conf|Deviation|Tolerance|Threshold|Bounds|Band|"
    r"Sanity|Positive|NonZero|Zero)[A-Za-z0-9_]*\s*\("
)

_FRESHNESS_GUARD_RE = re.compile(
    r"(?is)\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:fresh|stale|staleness|heartbeat|maxAge|max_age|maxStaleness|"
    r"max_staleness|maxDelay|max_delay|ttl|TTL|updatedAt|UpdatedAt|"
    r"timestamp|Timestamp|publishTime|PublishTime|lastUpdate|"
    r"LastUpdate|BlockTime|blockTime|time\.Now|now)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
)

_QUALITY_GUARD_RE = re.compile(
    r"(?is)\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:confidence|Confidence|conf|Conf|maxConfidence|max_confidence|"
    r"deviation|Deviation|maxDeviation|max_deviation|maxChange|"
    r"max_change|threshold|Threshold|tolerance|Tolerance|bounds|Bounds|"
    r"band|Band|sanity|Sanity|absDiff|abs_diff|delta|Delta|spread|"
    r"Spread|bps|Bps|basisPoints|minPrice|MinPrice|maxPrice|MaxPrice|"
    r"zero|Zero|positive|Positive|IsZero)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
)

_ZERO_GUARD_RE = re.compile(
    r"(?is)\bif\s+[^{}]{0,620}"
    r"(?:price|Price|value|Value|median|Median|index|Index|threshold|"
    r"Threshold|quote|Quote|answer|Answer)[^{}]{0,180}"
    r"(?:==|<=|<)\s*0[^{}]{0,620}"
    r"\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
)

_PURE_HELPER_NAME_RE = re.compile(
    r"^(?:Get|Read|Fetch|Load|Compute|Calculate|Calc|Store|Record)"
    r"[A-Za-z0-9_]*(?:Age|Staleness|Freshness|Delay|Lag|Timestamp|"
    r"Metric|Telemetry|Stats|Debug|Log|Snapshot)$",
    re.IGNORECASE,
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments_and_strings(src: str) -> str:
    src = _COMMENT_RE.sub(_blank, src)
    return _STRING_RE.sub(_blank, src)


def _has_guard_before(text: str, offset: int) -> bool:
    prefix = text[:offset]
    return bool(
        _VALIDATION_CALL_RE.search(prefix)
        or _FRESHNESS_GUARD_RE.search(prefix)
        or _QUALITY_GUARD_RE.search(prefix)
        or _ZERO_GUARD_RE.search(prefix)
    )


def _first_unsafe_sink(tail: str) -> re.Match[str] | None:
    for match in _STATE_SINK_RE.finditer(tail[:1800]):
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        return match
    return None


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None

    for read_match in _ORACLE_READ_RE.finditer(body_text):
        tail = body_text[read_match.end():]
        sink_match = _first_unsafe_sink(tail)
        if sink_match is None:
            continue

        sink_offset = read_match.end() + sink_match.start()
        if _has_guard_before(body_text, sink_offset):
            continue

        return (
            "oracle value reaches settlement, margin, liquidation, debt, "
            "reserve, or funding state before any freshness, heartbeat, "
            "confidence, zero-value, or deviation guard"
        )
    return None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue

        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
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
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` accepts an oracle price, median, index, "
                    f"threshold, or quote without price-quality validation: "
                    f"{reason}. Reject stale feeds, heartbeat misses, "
                    f"high-confidence intervals, zero or negative values, "
                    f"and excessive deviation before writing protocol risk "
                    f"or settlement state. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
