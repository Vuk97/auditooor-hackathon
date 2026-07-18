"""
go-oracle-pair-binding-fire35.py

Fire35 Go lift for oracle-price-manipulation.

Flags Go oracle or price keeper paths where an oracle price, median, TWAP,
or threshold has some source or quality validation before the state write, but
that validation is not bound to the exact pair, market id, asset, base denom,
quote denom, source, or feed being written.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- source refs:
  - reports/detector_lift_fire34_20260605/post_priorities_go.md
  - reference/patterns.dsl.r74_mined_cs/oracle-price-manipulation.yaml
  - detectors/go_wave1/go-oracle-manipulation-fire34.py
  - detectors/go_wave1/go-oracle-threshold-stale-fire33.py

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40 and R80 proof still require a real in-scope PoC before any finding can
cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re


DETECTOR_ID = "go_wave1.go-oracle-pair-binding-fire35"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|median|thresholdPrice|threshold|twap|TWAP|quote|"
    r"sourceID|SourceID|feedID|FeedID|baseDenom|quoteDenom)",
    re.IGNORECASE,
)

_ORACLE_READ_RE = re.compile(
    r"(?is)("
    r"(?:oracle|priceFeed|price_feed|feed|aggregator|pyth|chainlink|"
    r"slinky|provider|source|marketPrices|prices|indexer|medianFeed|"
    r"thresholdFeed|twapFeed|TWAPFeed)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,4}"
    r"\s*\.\s*(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|"
    r"Threshold|Twap|TWAP|Spot|Market|Report|Submit)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports)?\s*\(|"
    r"\b(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|Threshold|"
    r"Twap|TWAP|Spot|Market|Report)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports)\s*\(|"
    r"\b(?:report|median|twap|threshold|price|quote|oraclePrice|"
    r"marketPrice|markPrice|spotPrice|indexPrice|medianPrice|"
    r"thresholdPrice|twapPrice)\s*(?::=|=)"
    r")"
)

_STATE_MAP_WRITE_RE = re.compile(
    r"(?is)\b(?:k\.)?"
    r"(?P<state>(?:market|oracle|accepted|median|twap|TWAP|threshold|"
    r"index|spot|mark|price|prices|source|feed)[A-Za-z0-9_]*"
    r"(?:Prices|Price|Reports|Report|Medians|Median|TWAPs|Twaps|Twap|"
    r"Thresholds|Threshold|Sources|Source|Feeds|Feed|State|Cache))"
    r"\s*\[\s*(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*\]"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|:=|\+=|-=|\*=|/=)"
)

_STATE_SETTER_RE = re.compile(
    r"(?is)\.(?:Set|Update|Accept|Store|Write|Record)"
    r"[A-Za-z0-9_]*(?:Oracle|Market|Index|Median|Twap|TWAP|Threshold|"
    r"Price|Report)[A-Za-z0-9_]*\s*\((?P<args>[^{}\n;]{0,320})\)"
)

_SAFE_STATE_RE = re.compile(
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|event)",
    re.IGNORECASE,
)

_KEY_NAME_RE = re.compile(
    r"(pair|market|asset|base|quote|denom|source|feed|symbol|ticker)",
    re.IGNORECASE,
)

_KEY_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:ID|Id|Key)?\b"
)

_PAIR_RELATED_TOKEN_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:pair|market|base|quote|denom|asset)"
    r"[A-Za-z0-9_]*(?:ID|Id|Key)?\b",
    re.IGNORECASE,
)

_REPORT_VAR_RE = re.compile(
    r"\b(report|priceReport|oracleReport|median|twap|threshold|quote|"
    r"price|update|oracleUpdate)\b",
    re.IGNORECASE,
)

_PAIR_BIND_FIELD_RE = (
    r"(?:Pair|PairID|PairId|MarketID|MarketId|Market|Asset|AssetID|"
    r"AssetId|Base|BaseAsset|BaseDenom|Quote|QuoteAsset|QuoteDenom|"
    r"Denom|SourceID|SourceId|FeedID|FeedId|Feed|Source|Ticker|Symbol)"
)

_QUALITY_OR_IDENTITY_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
    r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Median|Twap|TWAP|Threshold|"
    r"Deviation|Tolerance|Bounds|Band|Sanity|Confidence|Conf|Quorum|"
    r"Source|Provider|Feed|Market|Pair|Asset|Base|Quote|Denom)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b(?:if|switch)\s+[^{}]{0,1100}"
    r"(?:sourceID|SourceID|sourceId|SourceId|feedID|FeedID|feedId|"
    r"FeedId|provider|Provider|oracleID|OracleID|marketID|MarketID|"
    r"marketId|MarketId|pair|Pair|asset|Asset|base|Base|quote|Quote|"
    r"denom|Denom|symbol|Symbol|ticker|Ticker|median|Median|twap|"
    r"TWAP|threshold|Threshold|confidence|Confidence|deviation|"
    r"Deviation|maxDeviation|max_deviation|maxChange|max_change|"
    r"tolerance|Tolerance|bounds|Bounds|band|Band|spread|Spread|"
    r"bps|Bps|basisPoints|window|Window|quorum|signers|Signers)"
    r"[^{}]{0,1100}\{[^{}]{0,700}\b(?:return|panic|Err|error)\b"
    r")"
)

_FRESHNESS_ONLY_RE = re.compile(
    r"(?is)(fresh|stale|staleness|heartbeat|maxAge|max_age|"
    r"updatedAt|UpdatedAt|timestamp|Timestamp|publishTime|PublishTime)"
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


def _looks_like_binding_key(name: str) -> bool:
    return bool(_KEY_NAME_RE.search(name))


def _all_pair_related_vars(text: str) -> set[str]:
    return {match.group(0) for match in _PAIR_RELATED_TOKEN_RE.finditer(text)}


def _related_keys_for(write_key: str, fn_text: str, body_text: str) -> set[str]:
    related = {write_key}
    lowered = write_key.lower()
    if "pair" in lowered or "market" in lowered:
        related.update(_all_pair_related_vars(fn_text))
        related.update(_all_pair_related_vars(body_text))
    return {key for key in related if _looks_like_binding_key(key)}


def _iter_price_sinks(body_text: str) -> list[tuple[int, str, str]]:
    sinks: list[tuple[int, str, str]] = []
    for match in _STATE_MAP_WRITE_RE.finditer(body_text):
        state = match.group("state")
        key = match.group("key")
        if _SAFE_STATE_RE.search(state):
            continue
        if not _looks_like_binding_key(key):
            continue
        sinks.append((match.start(), key, match.group(0)))

    for match in _STATE_SETTER_RE.finditer(body_text):
        snippet = match.group(0)
        if _SAFE_STATE_RE.search(snippet):
            continue
        args = match.group("args")
        for token in _KEY_TOKEN_RE.findall(args):
            if _looks_like_binding_key(token):
                sinks.append((match.start(), token, snippet))
                break
    return sorted(sinks, key=lambda item: item[0])


def _guard_matches(prefix: str) -> list[re.Match[str]]:
    matches = []
    for match in _QUALITY_OR_IDENTITY_GUARD_RE.finditer(prefix):
        guard_text = match.group(0)
        if _FRESHNESS_ONLY_RE.search(guard_text) and not re.search(
            r"(?i)(source|feed|market|pair|asset|base|quote|denom|median|"
            r"twap|threshold|confidence|deviation|tolerance|bounds|band|"
            r"spread|quorum|signer)",
            guard_text,
        ):
            continue
        matches.append(match)
    return matches


def _helper_call_binds_key(prefix: str, keys: set[str]) -> bool:
    for call in re.finditer(
        r"(?is)\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
        r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Median|Twap|TWAP|Threshold|"
        r"Source|Feed|Market|Pair|Asset|Base|Quote|Denom)"
        r"[A-Za-z0-9_]*\s*\((?P<args>[^)]{0,420})\)",
        prefix,
    ):
        args = call.group("args")
        if not _REPORT_VAR_RE.search(args):
            continue
        if any(re.search(rf"\b{re.escape(key)}\b", args) for key in keys):
            return True
    return False


def _direct_field_binds_key(prefix: str, keys: set[str]) -> bool:
    report_ref = r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*" + _PAIR_BIND_FIELD_RE + r")"
    for key in keys:
        key_ref = rf"\b{re.escape(key)}\b"
        direct = re.compile(
            rf"(?is)(?:{report_ref}\s*(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
            rf"[^{{}}\n;]{{0,120}}{key_ref}|"
            rf"{key_ref}[^{{}}\n;]{{0,120}}(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
            rf"[^{{}}\n;]{{0,120}}{report_ref})"
        )
        if direct.search(prefix):
            return True
    return False


def _keyed_lookup_binds_source(prefix: str, keys: set[str]) -> bool:
    for key in keys:
        keyed_lookup = re.compile(
            rf"(?is)\b(?:expected|allowed|trusted|canonical|configured)"
            rf"[A-Za-z0-9_]*(?:Source|Sources|Feed|Feeds|Oracle|Oracles|"
            rf"Market|Markets|Pair|Pairs|Asset|Assets|Denom|Denoms)"
            rf"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
            rf"\s*\[\s*{re.escape(key)}\s*\]"
        )
        if not keyed_lookup.search(prefix):
            continue

        direct_comparison = re.compile(
            rf"(?is)(?:SourceID|SourceId|FeedID|FeedId|Provider|OracleID)"
            rf"[^{{}}\n;]{{0,180}}(?:!=|==|\.Equal\s*\(|\.Equals\s*\()"
            rf"[^{{}}\n;]{{0,220}}(?:\[\s*{re.escape(key)}\s*\]|expected|"
            rf"trusted|canonical|configured)"
        )
        if direct_comparison.search(prefix):
            return True

        if re.search(
            r"(?is)\b(?:expected|trusted|canonical|configured)[A-Za-z0-9_]*"
            r"\s*:=\s*[^;\n]+",
            prefix,
        ) and re.search(
            r"(?is)(?:SourceID|SourceId|FeedID|FeedId|Provider|OracleID)"
            r"[^{}]{0,220}(?:!=|==)[^{}]{0,220}(?:expected|trusted|"
            r"canonical|configured)",
            prefix,
        ):
            return True
    return False


def _has_pair_bound_validation(prefix: str, write_key: str, fn_text: str, body_text: str) -> bool:
    keys = _related_keys_for(write_key, fn_text, body_text)
    if not keys:
        return False
    return (
        _helper_call_binds_key(prefix, keys)
        or _direct_field_binds_key(prefix, keys)
        or _keyed_lookup_binds_source(prefix, keys)
    )


def _candidate_reason(name: str, fn_text: str, body_text: str) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None
    if not (_ORACLE_READ_RE.search(body_text) or _ORACLE_CONTEXT_RE.search(body_text)):
        return None

    for sink_start, write_key, _sink_text in _iter_price_sinks(body_text):
        prefix = body_text[:sink_start]
        if _ORACLE_READ_RE.search(prefix) is None:
            continue
        guards = _guard_matches(prefix)
        if not guards:
            continue
        if _has_pair_bound_validation(prefix, write_key, fn_text, body_text):
            continue
        return (
            "oracle source, feed, median, TWAP, threshold, or deviation check "
            f"exists before the write, but it is not bound to write key `{write_key}`"
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
                    f"`{name}` validates an oracle price path without exact "
                    f"pair binding: {reason}. Bind the accepted price, median, "
                    f"TWAP, threshold, source, and feed to the same asset, "
                    f"market id, base denom, quote denom, or pair used by the "
                    f"state write. NOT_SUBMIT_READY source-review hit only. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
