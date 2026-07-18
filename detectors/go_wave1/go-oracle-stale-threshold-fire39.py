"""
go-oracle-stale-threshold-fire39.py

Fire39 Go lift for oracle-price-manipulation.

Flags Go oracle consumers that receive a timestamp-bearing price, quote,
median, threshold, or round report and let the report value reach liquidation,
settlement, margin, funding, reserve, debt, or risk state before a same-report
freshness guard is enforced. This narrows the Fire33 missing-validation miss
into stale-threshold semantics: the report type carries timestamp or round
metadata, but protocol state consumes the value before max-age, heartbeat,
updated-at, publish-time, or answered-in-round checks become load-bearing.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: oracle-price-manipulation
- context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
- context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
- MCP receipt: .auditooor/memory_context_receipt.json
- source refs:
  - reports/detector_lift_fire38_20260605/post_priorities_go.md
  - detectors/go_wave1/go-oracle-threshold-stale-fire33.py
  - detectors/go_wave1/go-oracle-threshold-enforcement-fire38.py

Detector hits are source-review candidates only and are NOT_SUBMIT_READY.
R40/R76/R80 caveat: detector hits are source-review candidates only, not
proof. R40, R76, and R80 proof still require a real in-scope PoC before any
finding can cite the result as load-bearing evidence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple


DETECTOR_ID = "go_wave1.go-oracle-stale-threshold-fire39"

_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(oracle|price|prices|priceFeed|price_feed|feed|aggregator|pyth|"
    r"chainlink|slinky|marketPrice|markPrice|indexPrice|spotPrice|"
    r"medianPrice|thresholdPrice|threshold|thresholds|twap|TWAP|quote|"
    r"quotes|round|Round|answeredInRound|updatedAt|publishTime|timestamp)",
    re.IGNORECASE,
)

_TIMESTAMP_FIELD_RE = re.compile(
    r"\b(?:UpdatedAt|updatedAt|UpdateTime|updateTime|Timestamp|timestamp|"
    r"PublishTime|publishTime|PublishedAt|publishedAt|StartedAt|startedAt|"
    r"BlockTime|blockTime|RoundID|RoundId|roundID|roundId|"
    r"AnsweredInRound|answeredInRound)\b"
)

_VALUE_FIELD_RE = re.compile(
    r"\b(?:Price|price|Prices|prices|Value|value|Answer|answer|Quote|quote|"
    r"Median|median|Index|index|Threshold|threshold|Rate|rate|Tick|tick)\b"
)

_TYPE_STRUCT_RE = re.compile(
    r"(?is)\btype\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+struct\s*"
    r"\{(?P<body>.*?)\}"
)

_FUNC_RESULT_RE = re.compile(
    r"(?is)\bfunc\s+(?:\([^)]*\)\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*"
    r"(?P<result>\([^{};]*\)|[A-Za-z_][A-Za-z0-9_]*)\s*\{"
)

_ORACLE_READ_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<vars>[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*"
    r"[A-Za-z_][A-Za-z0-9_]*)*)\s*(?::=|=)\s*"
    r"(?P<expr>[^{}\n;]{0,360}?"
    r"(?P<call>(?:Get|Read|Fetch|Load|Latest|Current|Median|Index|"
    r"Threshold|Twap|TWAP|Spot|Market|Report|Round)[A-Za-z0-9_]*"
    r"(?:Price|Prices|Quote|Quotes|Median|Index|Threshold|Rate|Tick|"
    r"Twap|TWAP|Report|Reports|Round|Rounds|Data)?))\s*\("
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
    r"thresholdPrices|medianPrices|twapPrices|reserves|collateral|debt|"
    r"margin|margins|funding|settlement|liquidations|positions|"
    r"healthFactors|notional)"
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
    r"(debug|metric|metrics|log|logger|telemetry|stat|stats|trace|cache|"
    r"cached|lastPrice|lastAccepted|baseline)",
    re.IGNORECASE,
)

_HELPER_FRESHNESS_RE = re.compile(
    r"(?is)\b(?:Ensure|Assert|Check|Validate|Require|Reject)"
    r"[A-Za-z0-9_]*(?:Oracle|Price|Quote|Fresh|Freshness|Stale|"
    r"Staleness|Heartbeat|Age|Timestamp|PublishTime|UpdatedAt|Round|"
    r"RoundID|RoundId|AnsweredInRound|Threshold)[A-Za-z0-9_]*\s*"
    r"\((?P<args>[^{};]{0,640})\)"
)

_INLINE_FRESHNESS_RE = re.compile(
    r"(?is)\b(?:if|switch)\s+[^{}]{0,1200}"
    r"(?:fresh|stale|staleness|heartbeat|maxAge|max_age|maxStaleness|"
    r"max_staleness|maxDelay|max_delay|ttl|TTL|updatedAt|UpdatedAt|"
    r"timestamp|Timestamp|publishTime|PublishTime|lastUpdate|"
    r"LastUpdate|BlockTime|blockTime|time\.Now|now|RoundID|RoundId|"
    r"roundID|roundId|AnsweredInRound|answeredInRound)"
    r"[^{}]{0,1200}\{[^{}]{0,900}\b(?:return|panic|Err|error)\b"
)

_PURE_HELPER_NAME_RE = re.compile(
    r"^(?:Get|Read|Fetch|Load|Compute|Calculate|Calc|Store|Record)"
    r"[A-Za-z0-9_]*(?:Age|Staleness|Freshness|Delay|Lag|Timestamp|"
    r"Metric|Telemetry|Stats|Debug|Log|Snapshot)$",
    re.IGNORECASE,
)


class SourceModel(NamedTuple):
    timestamp_report_types: frozenset[str]
    oracle_report_methods: frozenset[str]


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub(_blank, src)


def _strip_comments_and_strings(src: str) -> str:
    src = _strip_comments(src)
    return _STRING_RE.sub(_blank, src)


def _load_source(filepath: str, engine) -> str:
    try:
        return Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        source = getattr(engine, "source", b"")
        if isinstance(source, bytes):
            return source.decode("utf-8", errors="ignore")
        return str(source)


def _build_source_model(source: str) -> SourceModel:
    clean = _strip_comments_and_strings(source)
    timestamp_report_types: set[str] = set()
    for match in _TYPE_STRUCT_RE.finditer(clean):
        body = match.group("body")
        if _TIMESTAMP_FIELD_RE.search(body) and _VALUE_FIELD_RE.search(body):
            timestamp_report_types.add(match.group("name"))

    oracle_report_methods: set[str] = set()
    for match in _FUNC_RESULT_RE.finditer(clean):
        result = match.group("result")
        if not any(re.search(rf"\b{re.escape(t)}\b", result) for t in timestamp_report_types):
            continue
        name = match.group("name")
        if _ORACLE_CONTEXT_RE.search(name):
            oracle_report_methods.add(name)

    return SourceModel(
        timestamp_report_types=frozenset(timestamp_report_types),
        oracle_report_methods=frozenset(oracle_report_methods),
    )


def _first_assigned_var(vars_text: str) -> str | None:
    for item in (part.strip() for part in vars_text.split(",")):
        if item and item not in {"_", "err"}:
            return item
    return None


def _read_assignments(body_text: str, model: SourceModel) -> list[tuple[str, int, int, str]]:
    reads: list[tuple[str, int, int, str]] = []
    for match in _ORACLE_READ_ASSIGN_RE.finditer(body_text):
        var_name = _first_assigned_var(match.group("vars"))
        if var_name is None:
            continue
        expr = match.group("expr")
        call = match.group("call")
        if call not in model.oracle_report_methods and not _ORACLE_CONTEXT_RE.search(expr):
            continue
        reads.append((var_name, match.start(), match.end(), call))
    return reads


def _first_protocol_sink_after(body_text: str, offset: int) -> re.Match[str] | None:
    for match in _STATE_SINK_RE.finditer(body_text, offset):
        sink_text = match.group(0)
        if ":=" in sink_text and "k." not in sink_text and "[" not in sink_text:
            continue
        if _SAFE_SINK_RE.search(sink_text):
            continue
        return match
    return None


def _uses_report_value(var_name: str, text: str) -> bool:
    field_use = re.compile(
        rf"\b{re.escape(var_name)}\s*\.\s*"
        rf"(?:Price|price|Value|value|Answer|answer|Quote|quote|Median|"
        rf"median|Index|index|Threshold|threshold|Rate|rate|Tick|tick)\b"
    )
    return bool(field_use.search(text))


def _helper_freshness_guard(segment: str, var_name: str) -> bool:
    for match in _HELPER_FRESHNESS_RE.finditer(segment):
        if re.search(rf"\b{re.escape(var_name)}\b", match.group("args")):
            return True
    return False


def _inline_freshness_guard(segment: str, var_name: str) -> bool:
    for match in _INLINE_FRESHNESS_RE.finditer(segment):
        guard = match.group(0)
        has_report_time = re.search(
            rf"\b{re.escape(var_name)}\s*\.\s*"
            rf"(?:UpdatedAt|updatedAt|UpdateTime|updateTime|Timestamp|"
            rf"timestamp|PublishTime|publishTime|PublishedAt|publishedAt|"
            rf"StartedAt|startedAt|RoundID|RoundId|roundID|roundId|"
            rf"AnsweredInRound|answeredInRound)\b",
            guard,
        )
        if has_report_time:
            return True
    return False


def _has_freshness_guard(segment: str, var_name: str) -> bool:
    return _helper_freshness_guard(segment, var_name) or _inline_freshness_guard(segment, var_name)


def _candidate_reason(name: str, fn_text: str, body_text: str, model: SourceModel) -> str | None:
    if _PURE_HELPER_NAME_RE.match(name):
        return None
    if not _ORACLE_CONTEXT_RE.search(fn_text):
        return None

    for var_name, _read_start, read_end, call_name in _read_assignments(body_text, model):
        sink_match = _first_protocol_sink_after(body_text, read_end)
        if sink_match is None:
            continue

        before_sink = body_text[read_end:sink_match.start()]
        through_sink = body_text[read_end:sink_match.end()]
        if not _uses_report_value(var_name, through_sink):
            continue
        if _has_freshness_guard(before_sink, var_name):
            continue

        return (
            f"`{call_name}` returns timestamp-bearing oracle data assigned to "
            f"`{var_name}`, and a value field reaches protocol state before "
            "a same-report freshness, heartbeat, max-age, or round guard"
        )
    return None


def run(engine, filepath: str):
    source = _load_source(filepath, engine)
    model = _build_source_model(source)
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
        reason = _candidate_reason(name, fn_text, body_text, model)
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
                    f"`{name}` consumes stale-threshold oracle data before "
                    f"freshness enforcement: {reason}. Enforce updated-at, "
                    f"publish-time, heartbeat, max-age, or answered-in-round "
                    f"checks before writing liquidation, settlement, margin, "
                    f"funding, reserve, debt, or risk state. "
                    f"NOT_SUBMIT_READY source-review hit only. "
                    f"(class: oracle-price-manipulation)"
                ),
            }
        )
    return hits
