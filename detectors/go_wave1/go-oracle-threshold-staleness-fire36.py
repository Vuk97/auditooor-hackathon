"""
go-oracle-threshold-staleness-fire36.py

Fire36 Go lift for oracle-price-manipulation.

Flags Go oracle price update paths where a partial threshold, deviation,
freshness, pair, or cached-baseline check is present but not load-bearing
enough before the accepted price reaches protocol state. The detector focuses
on cases that Fire33 and Fire35 intentionally leave for a more specific lane:
stale rounds behind partial threshold checks, asymmetric min/max bounds,
global or unbound deviation baselines, and cached baseline mutation before the
deviation comparison.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire35_20260605/post_priorities_go.md
  - reference/patterns.dsl.r74_mined_cs/oracle-price-manipulation.yaml
  - detectors/go_wave1/go-oracle-pair-binding-fire35.py
  - detectors/go_wave1/go-oracle-threshold-stale-fire33.py

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before any finding can
cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-oracle-threshold-staleness-fire36"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|thresholdPrice|threshold|thresholds|twap|TWAP|"
    r"quote|quotes|report|reports|round|Round|baseline|lastPrice|"
    r"lastAccepted|cachedPrice)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source|marketPrices|prices|indexer|medianFeed|"
    r"thresholdFeed|twapFeed|TWAPFeed|reporter)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
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
    r"Seize|Payout|Mint|Redeem|Accept|Finalize|UpdateMarketPrice)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"(?:\bk\.|\b)(?:marketPrices|acceptedPrices|acceptedReports|"
    r"oracleReports|oracleState|priceState|riskState|riskPrices|thresholdPrices|"
    r"medianPrices|twapPrices|reserves|collateral|debt|margin|"
    r"margins|funding|settlement|liquidations|positions|healthFactors|"
    r"notional)"
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
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|"
    r"cache|cached|lastPrice|lastAccepted|baseline)",
    re.IGNORECASE,
)

_PURE_HELPER_NAME_RE = re.compile(
    r"^(?:Get|Read|Fetch|Load|Compute|Calculate|Calc|Store|Record)"
    r"[A-Za-z0-9_]*(?:Age|Staleness|Freshness|Delay|Lag|Timestamp|"
    r"Metric|Telemetry|Stats|Debug|Log|Snapshot)$",
    re.IGNORECASE,
)

_PAIR_VAR_RE = re.compile(
    r"\b(pair|pairID|pairId|asset|assetID|assetId|marketID|marketId|"
    r"market|denom|baseDenom|quoteDenom|symbol|ticker)\b"
)

_PAIR_KEYED_WRITE_RE = re.compile(
    r"(?is)\[(?P<key>pair|pairID|pairId|asset|assetID|assetId|marketID|"
    r"marketId|market|denom|baseDenom|quoteDenom|symbol|ticker|pairKey)\]"
)

_FRESHNESS_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Fresh|Freshness|Stale|Staleness|Heartbeat|Age|Timestamp|"
    r"PublishTime|UpdatedAt|Round|RoundID|RoundId|AnsweredInRound)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:fresh|stale|staleness|heartbeat|maxAge|max_age|maxStaleness|"
    r"max_staleness|maxDelay|ttl|TTL|updatedAt|UpdatedAt|timestamp|"
    r"Timestamp|publishTime|PublishTime|lastUpdate|LastUpdate|"
    r"roundID|RoundID|roundId|RoundId|AnsweredInRound|answeredInRound|"
    r"BlockTime|blockTime|time\.Now|now)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_LOWER_BOUND_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Min|Minimum|Positive|NonZero|Lower|Floor|Price|Threshold)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:price|Price|value|Value|quote|Quote|median|Median|index|Index|"
    r"threshold|Threshold|answer|Answer|rate|Rate)"
    r"[^{}]{0,220}(?:<=|<)\s*(?:0|k\.[A-Za-z0-9_]*(?:Min|Minimum|Floor)"
    r"[A-Za-z0-9_]*|min[A-Za-z0-9_]*|Min[A-Za-z0-9_]*)"
    r"[^{}]{0,620}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:min[A-Za-z0-9_]*|Min[A-Za-z0-9_]*|k\.[A-Za-z0-9_]*(?:Min|"
    r"Minimum|Floor)[A-Za-z0-9_]*)"
    r"[^{}]{0,220}(?:>=|>)\s*(?:price|Price|value|Value|quote|Quote|"
    r"median|Median|index|Index|threshold|Threshold)"
    r"[^{}]{0,620}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_UPPER_BOUND_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Max|Maximum|Upper|Ceil|Cap|Price|Threshold)\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:price|Price|value|Value|quote|Quote|median|Median|index|Index|"
    r"threshold|Threshold|answer|Answer|rate|Rate)"
    r"[^{}]{0,220}(?:>=|>)\s*(?:k\.[A-Za-z0-9_]*(?:Max|Maximum|Ceil|Cap)"
    r"[A-Za-z0-9_]*|max[A-Za-z0-9_]*|Max[A-Za-z0-9_]*)"
    r"[^{}]{0,620}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b|"
    r"\b(?:if|switch)\s+[^{}]{0,900}"
    r"(?:max[A-Za-z0-9_]*|Max[A-Za-z0-9_]*|k\.[A-Za-z0-9_]*(?:Max|"
    r"Maximum|Ceil|Cap)[A-Za-z0-9_]*)"
    r"[^{}]{0,220}(?:<=|<)\s*(?:price|Price|value|Value|quote|Quote|"
    r"median|Median|index|Index|threshold|Threshold)"
    r"[^{}]{0,620}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_DEVIATION_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Deviation|Tolerance|PriceBand|Bounds|Sanity|Threshold|Twap|TWAP)"
    r"\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:deviation|Deviation|maxDeviation|max_deviation|maxChange|"
    r"max_change|tolerance|Tolerance|bounds|Bounds|band|Band|sanity|"
    r"Sanity|absDiff|abs_diff|delta|Delta|spread|Spread|bps|Bps|"
    r"basisPoints)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_QUALITY_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Oracle|Price|Quote|Threshold|Deviation|Tolerance|Bounds|Band|"
    r"Sanity|Confidence|Conf|Quorum|Vote|Signer|Signature|Source|Feed|"
    r"Pair|Market|Asset|Denom|Positive|NonZero|Zero)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1000}"
    r"(?:confidence|Confidence|conf|Conf|maxConfidence|max_confidence|"
    r"quorum|requiredVotes|requiredReports|requiredSigners|voteCount|"
    r"votes|signerCount|signers|signatureCount|validators|sourceID|"
    r"SourceID|feedID|FeedID|provider|Provider|oracleID|OracleID)"
    r"[^{}]{0,1000}\{[^{}]{0,620}\b(?:return|panic|Err|error)\b"
    r")"
)

_PAIR_BINDING_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require)[A-Za-z0-9_]*"
    r"(?:Oracle|Price|Quote|Source|Provider|Feed|Market|Pair|Asset|Base|"
    r"Quote|Denom)[A-Za-z0-9_]*\s*\([^)]{0,420}\b(?:pair|pairID|"
    r"pairId|asset|assetID|assetId|marketID|marketId|market|denom|"
    r"baseDenom|quoteDenom|symbol|ticker)\b|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:PairID|PairId|Pair|MarketID|"
    r"MarketId|Market|AssetID|AssetId|Asset|BaseDenom|QuoteDenom|Denom|"
    r"SourceID|SourceId|FeedID|FeedId)"
    r"[^{}\n;]{0,180}(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
    r"[^{}\n;]{0,180}\b(?:pair|pairID|pairId|asset|assetID|assetId|"
    r"marketID|marketId|market|denom|baseDenom|quoteDenom|symbol|ticker)\b|"
    r"\b(?:expected|trusted|canonical|configured)[A-Za-z0-9_]*"
    r"(?:Source|Sources|Feed|Feeds|Oracle|Oracles|Market|Markets|Pair|"
    r"Pairs|Asset|Assets|Denom|Denoms)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*\[\s*(?:pair|pairID|pairId|"
    r"asset|assetID|assetId|marketID|marketId|market|denom|baseDenom|"
    r"quoteDenom|symbol|ticker|pairKey)\s*\]"
    r")"
)

_BASELINE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:k\.)?"
    r"(?:last|cached|baseline|previous|prior)[A-Za-z0-9_]*(?:Price|Prices|"
    r"Quote|Quotes|Median|Index|Threshold|Baseline|Baselines)"
    r"(?:\s*\[[^\]\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|:=)\s*[^;\n{}]{0,220}"
    r"(?:report|price|quote|median|index|threshold|oracleReport)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
)

_GLOBAL_BASELINE_RE = re.compile(
    r"(?is)\b(?:k\.)?(?:last|cached|baseline|previous|prior)"
    r"[A-Za-z0-9_]*(?:Price|Quote|Median|Index|Threshold|Baseline)"
    r"\b(?!\s*\[)"
)

_PAIR_KEYED_BASELINE_RE = re.compile(
    r"(?is)\b(?:k\.)?(?:last|cached|baseline|previous|prior)"
    r"[A-Za-z0-9_]*(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|"
    r"Baseline|Baselines)\s*\[\s*(?:pair|pairID|pairId|asset|assetID|"
    r"assetId|marketID|marketId|market|denom|baseDenom|quoteDenom|"
    r"symbol|ticker|pairKey)\s*\]"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub(_blank, src)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank, src)


def _first_protocol_sink(body_text: str) -> re.Match[str] | None:
    for match in _STATE_SINK_RE.finditer(body_text):
        if _SAFE_SINK_RE.search(match.group(0)):
            continue
        return match
    return None


def _pair_vars(text: str) -> set[str]:
    return {match.group(1) for match in _PAIR_VAR_RE.finditer(text)}


def _sink_is_pair_keyed(sink_text: str) -> bool:
    return bool(_PAIR_KEYED_WRITE_RE.search(sink_text))


def _has_freshness(prefix: str) -> bool:
    return bool(_FRESHNESS_GUARD_RE.search(prefix))


def _has_quality_without_freshness(prefix: str) -> bool:
    return bool(
        _QUALITY_GUARD_RE.search(prefix)
        or _LOWER_BOUND_GUARD_RE.search(prefix)
        or _UPPER_BOUND_GUARD_RE.search(prefix)
        or _DEVIATION_GUARD_RE.search(prefix)
        or _PAIR_BINDING_RE.search(prefix)
    )


def _asymmetric_minmax_reason(prefix: str) -> str | None:
    bound_prefix = _DEVIATION_GUARD_RE.sub(_blank, prefix)
    has_lower = bool(_LOWER_BOUND_GUARD_RE.search(bound_prefix))
    has_upper = bool(_UPPER_BOUND_GUARD_RE.search(bound_prefix))
    if has_lower and not has_upper:
        return "oracle price has a lower-bound or positive check but no upper-bound check"
    if has_upper and not has_lower:
        return "oracle price has an upper-bound check but no lower-bound or positive check"
    return None


def _cached_baseline_mutated_before_deviation(prefix: str) -> bool:
    mutation = _BASELINE_ASSIGN_RE.search(prefix)
    if mutation is None:
        return False
    later = prefix[mutation.end():]
    return bool(_DEVIATION_GUARD_RE.search(later))


def _global_baseline_reason(prefix: str, fn_text: str, sink_text: str) -> str | None:
    if not _DEVIATION_GUARD_RE.search(prefix):
        return None
    if not _pair_vars(fn_text) and not _sink_is_pair_keyed(sink_text):
        return None
    if _PAIR_KEYED_BASELINE_RE.search(prefix):
        return None
    if _GLOBAL_BASELINE_RE.search(prefix):
        return (
            "deviation or threshold guard compares against a global cached "
            "baseline while the accepted price is keyed by pair, market, asset, "
            "or denom"
        )
    return None


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None
    if not (_ORACLE_READ_RE.search(body_text) or _ORACLE_CONTEXT_RE.search(body_text)):
        return None

    sink = _first_protocol_sink(body_text)
    if sink is None:
        return None

    sink_start = sink.start()
    prefix = body_text[:sink_start]
    sink_text = sink.group(0)

    if _cached_baseline_mutated_before_deviation(prefix):
        return (
            "cached oracle baseline is overwritten from the new report before "
            "the deviation guard, making the threshold comparison non-load-bearing"
        )

    baseline_reason = _global_baseline_reason(prefix, fn_text, sink_text)
    if baseline_reason is not None:
        return baseline_reason

    minmax_reason = _asymmetric_minmax_reason(prefix)
    if minmax_reason is not None:
        return minmax_reason

    if _has_quality_without_freshness(prefix) and not _has_freshness(prefix):
        return (
            "price-quality, threshold, pair, or quorum validation exists before "
            "the state write, but no stale round, timestamp, heartbeat, or max-age "
            "guard protects the accepted price"
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
                    f"`{name}` accepts an oracle price after an incomplete "
                    f"threshold or staleness check: {reason}. Require "
                    f"pair-bound freshness, symmetric min/max bounds, and "
                    f"deviation checks against an immutable pre-update "
                    f"baseline before writing protocol risk state. "
                    f"NOT_SUBMIT_READY source-review hit only. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
