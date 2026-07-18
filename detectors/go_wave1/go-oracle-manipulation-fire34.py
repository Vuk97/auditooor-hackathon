"""
go-oracle-manipulation-fire34.py

Fire34 Go lift for oracle-price-manipulation.

Flags Go oracle consumers where validation appears present but is not
load-bearing at the price acceptance point: freshness, threshold, quorum,
denominator, or source checks run after the first protocol state write, are
skipped when falling back to cached or last-good prices, or compare against a
global source while a per-asset or per-pair feed context is available.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire33_20260605/post_priorities_go.md
  - detectors/go_wave1/go-oracle-threshold-stale-fire33.py
  - detectors/go_wave1/go-oracle-price-threshold-stale-fire32.py
  - reference/patterns.dsl/oracle-aggregator-report-processed-pre-quorum.yaml
  - reference/patterns.dsl/r94-loop-oracle-feed-id-mismatch.yaml
  - reference/patterns.dsl/glider-oracle-price-denominator-zero.yaml

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before any finding can
cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-oracle-manipulation-fire34"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|thresholdPrice|quote|quotes|twap|TWAP|report|"
    r"reports|sourceID|SourceID|feedID|FeedID)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source|marketPrices|prices|reports|reporter|"
    r"indexer)(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|"
    r"Threshold|Twap|TWAP|Spot|Market|Report|Submit)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports)?\s*\(|"
    r"\b(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|Threshold|"
    r"Twap|TWAP|Spot|Market|Report)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports)\s*\(|"
    r"\b(?:price|quote|oraclePrice|marketPrice|markPrice|spotPrice|"
    r"indexPrice|medianPrice|thresholdPrice|twapPrice|lastPrice|"
    r"cachedPrice|report|oracleReport)\s*(?::=|=)"
    r")"
)

_STATE_SINK_RE = re.compile(
    r"(?is)("
    r"\.(?:Settle|SettleFunding|SettleLiquidation|Liquidate|"
    r"MarkLiquidated|OpenPosition|UpdateMargin|RepriceMargin|ApplyMargin|"
    r"UpdateReserve|SetReserve|SettleReserve|UpdateDebt|Borrow|Repay|"
    r"Seize|Payout|Mint|Redeem|Accept|Finalize)[A-Za-z0-9_]*\s*\(|"
    r"(?:\bk\.|\b)(?:marketPrices|acceptedPrices|lastAcceptedPrices|"
    r"acceptedReports|oracleReports|oracleState|priceState|riskState|"
    r"reserves|collateral|debt|margin|margins|funding|settlement|"
    r"liquidations|positions|healthFactors|notional)"
    r"(?:\s*\[[^\]\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|:=|\+=|-=|\*=|/=)|"
    r"\b(?:settlement|settle|margin|liquidation|liquidat|reserve|"
    r"reserves|collateral|debt|borrow|repay|health|solvency|position|"
    r"funding|payout|seized|notional)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]\n]+\])?\s*(?:=|\+=|-=|\*=|/=)"
    r")"
)

_SAFE_SINK_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace)",
    re.IGNORECASE,
)

_VALIDATION_CALL_RE = re.compile(
    r"(?is)\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
    r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Fresh|Freshness|Stale|"
    r"Staleness|Heartbeat|Age|Timestamp|PublishTime|UpdatedAt|"
    r"Confidence|Conf|Deviation|Tolerance|Threshold|Bounds|Band|"
    r"Sanity|Positive|NonZero|Zero|Quorum|Vote|Signer|Signature|"
    r"Source|Provider|Feed|Denom|Denominator|Scale|Decimals)"
    r"[A-Za-z0-9_]*\s*\("
)

_TIMESTAMP_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Fresh|Freshness|Stale|Staleness|Heartbeat|Age|Timestamp|"
    r"PublishTime|UpdatedAt)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:fresh|stale|staleness|heartbeat|maxAge|max_age|maxStaleness|"
    r"max_staleness|maxDelay|ttl|TTL|updatedAt|UpdatedAt|timestamp|"
    r"Timestamp|publishTime|PublishTime|lastUpdate|LastUpdate|"
    r"BlockTime|blockTime|time\.Now|now)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_THRESHOLD_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Deviation|Tolerance|PriceBand|Bounds|Sanity|Threshold|"
    r"Confidence|Conf|Twap|TWAP)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:confidence|Confidence|conf|Conf|maxConfidence|max_confidence|"
    r"deviation|Deviation|maxDeviation|max_deviation|maxChange|"
    r"max_change|threshold|Threshold|tolerance|Tolerance|bounds|Bounds|"
    r"band|Band|sanity|Sanity|absDiff|abs_diff|delta|Delta|spread|"
    r"Spread|bps|Bps|basisPoints|minPrice|MinPrice|maxPrice|MaxPrice)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_QUORUM_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Quorum|Vote|Votes|Signer|Signers|Signature|Report|Reports)"
    r"\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:quorum|requiredVotes|requiredReports|requiredSigners|"
    r"voteCount|votes|signerCount|signers|signatureCount|validators|"
    r"validatorCount|minReports|minQuorum|memberCount|reports)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_DENOMINATOR_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Denom|Denominator|Scale|Decimals|Positive|NonZero|Zero|Price)"
    r"\s*\(|"
    r"\bif\s+[^{}]{0,900}"
    r"(?:price|Price|value|Value|quote|Quote|answer|Answer|rate|Rate|"
    r"denom|Denom|denominator|Denominator|scale|Scale|decimals|"
    r"Decimals)[^{}]{0,220}(?:==|<=|<)\s*0"
    r"[^{}]{0,620}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_SOURCE_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Source|Provider|Feed|Oracle|MarketID|Pair|Asset|Denom)"
    r"\s*\(|"
    r"\b(?:IsTrustedSource|TrustedSource|AllowedSource|SourceAllowed|"
    r"AllowedFeed|TrustedFeed)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:sourceID|SourceID|sourceId|SourceId|feedID|FeedID|feedId|"
    r"provider|Provider|oracleID|OracleID|oracleId|marketID|MarketID|"
    r"pair|Pair|asset|Asset|denom|Denom)"
    r"[^{}]{0,360}(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_FALLBACK_TOKEN_RE = re.compile(
    r"(?is)\b(?:fallback|Fallback|backup|Backup|secondary|Secondary|"
    r"lastGood|LastGood|lastKnown|LastKnown|cached|Cached|cache|Cache|"
    r"lastPrice|LastPrice|previous|Previous)[A-Za-z0-9_]*\b"
)

_PAIR_VAR_RE = re.compile(
    r"\b(pair|asset|marketID|marketId|market|denom|baseDenom|quoteDenom|"
    r"symbol|ticker)\b"
)

_SOURCE_MAP_CONTEXT_RE = re.compile(
    r"(?is)\b(?:expectedSources|expectedSource|expectedFeeds|"
    r"expectedFeed|feedByPair|feedsByPair|feedByAsset|feedsByAsset|"
    r"assetFeeds|pairFeeds|marketFeeds|oracleByPair|oracleByAsset|"
    r"oracleByMarket|sourcesByPair|sourcesByAsset|sourcesByMarket|"
    r"trustedFeeds|allowedFeeds|canonicalFeeds)\b"
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


def _first_unsafe_sink(body_text: str) -> re.Match[str] | None:
    for match in _STATE_SINK_RE.finditer(body_text):
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        return match
    return None


def _guard_families_in(text: str) -> set[str]:
    families: set[str] = set()
    if _TIMESTAMP_GUARD_RE.search(text):
        families.add("timestamp")
    if _THRESHOLD_GUARD_RE.search(text):
        families.add("threshold")
    if _QUORUM_GUARD_RE.search(text):
        families.add("quorum")
    if _DENOMINATOR_GUARD_RE.search(text):
        families.add("denominator")
    if _SOURCE_GUARD_RE.search(text):
        families.add("source")
    return families


def _late_guard_reason(body_text: str, sink_start: int) -> str | None:
    before = body_text[:sink_start]
    after = body_text[sink_start:]
    before_families = _guard_families_in(before)
    after_families = _guard_families_in(after)
    late = sorted(after_families - before_families)
    if not late:
        return None
    return (
        "validation family applied after first protocol state write: "
        + ", ".join(late)
    )


def _fallback_skip_reason(body_text: str, sink_start: int) -> str | None:
    prefix = body_text[:sink_start]
    for fallback in _FALLBACK_TOKEN_RE.finditer(prefix):
        read_before_fallback = _ORACLE_READ_RE.search(prefix[:fallback.start()])
        if read_before_fallback is None:
            continue

        between = prefix[fallback.end():]
        if _VALIDATION_CALL_RE.search(between) or _guard_families_in(between):
            continue

        return (
            "fallback, cached, or last-good oracle value reaches protocol state "
            "without a validation call on the fallback value"
        )
    return None


def _pair_vars(text: str) -> set[str]:
    return {m.group(1) for m in _PAIR_VAR_RE.finditer(text)}


def _source_guard_is_pair_bound(prefix: str, guard: re.Match[str], pair_vars: set[str]) -> bool:
    guard_text = guard.group(0)
    if any(re.search(rf"\b{re.escape(var)}\b", guard_text) for var in pair_vars):
        return True

    before_guard = prefix[:guard.start()]
    for var in pair_vars:
        indexed_lookup = re.compile(
            rf"(?is)\b(?:expectedSources|expectedSource|expectedFeeds|"
            rf"expectedFeed|feedByPair|feedsByPair|feedByAsset|feedsByAsset|"
            rf"assetFeeds|pairFeeds|marketFeeds|oracleByPair|oracleByAsset|"
            rf"oracleByMarket|sourcesByPair|sourcesByAsset|sourcesByMarket|"
            rf"trustedFeeds|allowedFeeds|canonicalFeeds)"
            rf"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
            rf"\s*\[\s*{re.escape(var)}\s*\]"
        )
        if indexed_lookup.search(before_guard):
            return True
    return False


def _pair_unbound_source_reason(fn_text: str, body_text: str, sink_start: int) -> str | None:
    prefix = body_text[:sink_start]
    source_guard = _SOURCE_GUARD_RE.search(prefix)
    if source_guard is None:
        return None
    if not _SOURCE_MAP_CONTEXT_RE.search(fn_text):
        return None

    pair_vars = _pair_vars(fn_text)
    if not pair_vars:
        return None
    if _source_guard_is_pair_bound(prefix, source_guard, pair_vars):
        return None

    return (
        "source or feed identity check is global and not tied to the "
        "available asset, pair, market, or denom feed context"
    )


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None
    if not (_ORACLE_READ_RE.search(body_text) or _ORACLE_CONTEXT_RE.search(body_text)):
        return None

    sink = _first_unsafe_sink(body_text)
    if sink is None:
        return None

    sink_start = sink.start()
    for finder in (
        _fallback_skip_reason,
        _late_guard_reason,
    ):
        reason = finder(body_text, sink_start)
        if reason is not None:
            return reason

    return _pair_unbound_source_reason(fn_text, body_text, sink_start)


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
                    f"`{name}` accepts an oracle price after a non-load-bearing "
                    f"validation pattern: {reason}. Require freshness, "
                    f"threshold, quorum, denominator, and pair-bound source "
                    f"validation before any protocol state write or fallback "
                    f"acceptance. NOT_SUBMIT_READY source-review hit only. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
