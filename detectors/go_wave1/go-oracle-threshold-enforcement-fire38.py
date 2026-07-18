"""
go-oracle-threshold-enforcement-fire38.py

Fire38 Go lift for oracle-price-manipulation.

Flags Go oracle acceptance paths where threshold, staleness,
answered-in-round, version, or timestamp guard inputs are configured or
computed, but no rejecting guard is enforced before the price is returned or
stored in protocol state. This complements Fire33's missing-validation shape
and Fire36's partial staleness or threshold shape by focusing on
non-load-bearing guard inputs.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire37_20260605/post_priorities_go.md
  - detectors/go_wave1/go-oracle-threshold-stale-fire33.py
  - detectors/go_wave1/go-oracle-threshold-staleness-fire36.py
  - .auditooor/memory_context_receipt.json

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before any finding can
cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-oracle-threshold-enforcement-fire38"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|thresholdPrice|twap|TWAP|quote|quotes|report|"
    r"round|Round|answeredInRound|AnsweredInRound|version|Version|"
    r"timestamp|Timestamp|updatedAt|UpdatedAt)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source|prices|reports|reporter|thresholdFeed|"
    r"threshold_feed|roundFeed|round_feed|indexer)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|"
    r"Threshold|Twap|TWAP|Spot|Market|Report|Round)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports|Round|Rounds|Data)?\s*\(|"
    r"\b(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|Threshold|"
    r"Twap|TWAP|Spot|Market|Report|Round)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports|Round|Rounds|Data)\s*\(|"
    r"\b(?:price|quote|oraclePrice|marketPrice|markPrice|spotPrice|"
    r"indexPrice|medianPrice|thresholdPrice|twapPrice|lastPrice|"
    r"cachedPrice|report|oracleReport|roundData)\s*(?::=|=)"
    r")"
)

_STATE_SINK_RE = re.compile(
    r"(?is)("
    r"\.(?:Settle|SettleFunding|SettleLiquidation|Liquidate|"
    r"MarkLiquidated|OpenPosition|UpdateMargin|RepriceMargin|ApplyMargin|"
    r"UpdateReserve|SetReserve|SettleReserve|UpdateDebt|Borrow|Repay|"
    r"Seize|Payout|Mint|Redeem|Accept|Finalize|UpdateMarketPrice)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"(?:\bk\.|\b)(?:marketPrices|acceptedPrices|acceptedReports|"
    r"oracleReports|oracleState|priceState|riskState|riskPrices|"
    r"thresholdPrices|medianPrices|twapPrices|roundPrices|reserves|"
    r"collateral|debt|margin|margins|funding|settlement|liquidations|"
    r"positions|healthFactors|notional)"
    r"(?:\s*\[[^\]\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|:=|\+=|-=|\*=|/=)|"
    r"\b(?:settlement|settle|margin|liquidation|liquidat|reserve|"
    r"reserves|collateral|debt|borrow|repay|health|solvency|position|"
    r"funding|payout|seized|notional)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]\n]+\])?\s*(?:=|\+=|-=|\*=|/=)"
    r")"
)

_RETURN_PRICE_RE = re.compile(
    r"(?is)\breturn\s+"
    r"(?P<expr>[^{}\n;]{0,240}"
    r"(?:"
    r"\b(?:price|Price|answer|Answer|value|Value|quote|Quote|median|"
    r"Median|index|Index|threshold|Threshold)\b|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:Price|Answer|Value|Median|"
    r"Index|Threshold|Rate)"
    r")"
    r"[^{}\n;]{0,240})"
)

_SAFE_SINK_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|"
    r"cache|cached|lastPrice|lastAccepted|baseline)",
    re.IGNORECASE,
)

_GUARD_INPUT_RE = re.compile(
    r"(?is)("
    r"\b(?:maxAge|max_age|maxStaleness|max_staleness|maxDelay|max_delay|"
    r"heartbeat|ttl|TTL|minTimestamp|maxTimestamp|minUpdatedAt|"
    r"maxUpdatedAt|minRound|minRoundID|minRoundId|requiredRound|"
    r"requiredRoundID|requiredRoundId|minAnsweredInRound|"
    r"expectedAnsweredInRound|minVersion|expectedVersion|maxVersion|"
    r"oracleVersion|feedVersion|stale|tooOld|fresh|freshness|roundFresh|"
    r"roundOK|answeredRoundOK|versionOK|versionMatches|timestampOK|"
    r"thresholdOK|minAnswer|maxAnswer|minPrice|maxPrice|bounds|"
    r"threshold|thresholds)\b|"
    r"\b(?:AnsweredInRound|answeredInRound|RoundID|RoundId|roundID|"
    r"roundId|Version|version|UpdatedAt|updatedAt|Timestamp|timestamp|"
    r"PublishTime|publishTime|StartedAt|startedAt)\b"
    r")"
)

_ENFORCING_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
    r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Fresh|Freshness|Stale|"
    r"Staleness|Heartbeat|Age|Timestamp|PublishTime|UpdatedAt|Round|"
    r"AnsweredInRound|Version|Threshold|Bounds|Band|Min|Max|Positive|"
    r"NonZero|Sanity)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1200}"
    r"(?:maxAge|max_age|maxStaleness|max_staleness|maxDelay|max_delay|"
    r"heartbeat|ttl|TTL|minTimestamp|maxTimestamp|minUpdatedAt|"
    r"AnsweredInRound|answeredInRound|RoundID|RoundId|roundID|roundId|"
    r"Version|version|UpdatedAt|updatedAt|Timestamp|timestamp|"
    r"PublishTime|publishTime|StartedAt|startedAt|stale|tooOld|fresh|"
    r"roundFresh|roundOK|answeredRoundOK|versionOK|versionMatches|"
    r"timestampOK|thresholdOK|minAnswer|maxAnswer|minPrice|maxPrice|"
    r"bounds|threshold|thresholds)"
    r"[^{}]{0,1200}\{[^{}]{0,900}\b(?:return|panic|Err|error)\b"
    r")"
)

_PURE_HELPER_NAME_RE = re.compile(
    r"^(?:Get|Read|Fetch|Load|Compute|Calculate|Calc|Store|Record)"
    r"[A-Za-z0-9_]*(?:Age|Staleness|Freshness|Delay|Lag|Timestamp|"
    r"Metric|Telemetry|Stats|Debug|Log|Snapshot)$",
    re.IGNORECASE,
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub(_blank, src)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank, src)


def _acceptance_points(body_text: str) -> list[tuple[int, int, str]]:
    points: list[tuple[int, int, str]] = []
    for match in _STATE_SINK_RE.finditer(body_text):
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        points.append((match.start(), match.end(), "state write"))
    for match in _RETURN_PRICE_RE.finditer(body_text):
        points.append((match.start(), match.end(), "price return"))
    return sorted(points)


def _first_acceptance_after_oracle_read(body_text: str) -> tuple[int, int, str] | None:
    read = _ORACLE_READ_RE.search(body_text)
    if read is None:
        return None

    for start, end, kind in _acceptance_points(body_text):
        if start > read.end():
            return (start, end, kind)
    return None


def _has_enforcing_guard(text: str) -> bool:
    return bool(_ENFORCING_GUARD_RE.search(text))


def _has_guard_input(text: str) -> bool:
    return bool(_GUARD_INPUT_RE.search(text))


def _late_guard_reason(body_text: str, accept_end: int) -> str | None:
    tail = body_text[accept_end: accept_end + 1800]
    if _has_enforcing_guard(tail):
        return (
            "threshold, staleness, answered-in-round, version, or timestamp "
            "guard appears only after the first price acceptance point"
        )
    return None


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None

    acceptance = _first_acceptance_after_oracle_read(body_text)
    if acceptance is None:
        return None

    accept_start, accept_end, accept_kind = acceptance
    prefix = body_text[:accept_start]
    if _has_enforcing_guard(prefix):
        return None

    late_reason = _late_guard_reason(body_text, accept_end)
    if late_reason is not None:
        return f"{late_reason} before {accept_kind}"

    if _has_guard_input(prefix):
        return (
            "guard configuration or computed guard input is present before "
            f"{accept_kind}, but no rejecting oracle guard is enforced first"
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

        raw_fn_text = engine.text(fn)
        fn_text = _strip_comments(raw_fn_text)
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
                "snippet": raw_fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` accepts an oracle price with a non-load-bearing "
                    f"threshold or freshness enforcement path: {reason}. "
                    f"Enforce max-age, timestamp, answered-in-round, version, "
                    f"and threshold checks before returning or storing the "
                    f"price. NOT_SUBMIT_READY source-review hit only. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
