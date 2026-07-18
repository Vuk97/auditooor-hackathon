#!/usr/bin/env python3
"""DeepSeek monitoring dashboard - real-time spend + budget alerts + verification_tier gate.

Aggregates real-time spend from:
  - ``.auditooor/llm_dispatch_log.jsonl``                (canonical dispatch log)
  - ``.auditooor/deepseek_fanout/<run>/monitor.jsonl``   (per-run fanout monitor)

For each lane, emits a markdown + JSON dashboard containing:
  - Provider/since-window header
  - Call counts (success / failed / insufficient_balance / other_error)
  - Tokens in (cache-miss + cache-hit) / tokens out
  - Cost breakdown (cache-miss USD + cache-hit USD + output USD)
  - Latency stats (avg / p50 / p95 / p99)
  - Verification-tier distribution (tier-1 percentage; tier-3 percentage)
  - Anomaly status (cost-spike, failure-rate-spike, latency-spike, tier-drift)
  - Per-task-type breakdown (TOK-A..TOK-F)
  - Budget MTD: spent vs cap, alert-threshold-USD trigger state

Budget alert side-effects:
  - 50% MTD spend  -> stderr INFO line
  - 80% MTD spend  -> stderr WARN line + ``.auditooor/budget_alerts.jsonl`` row
  - 100% MTD spend -> stderr EXCEEDED line + ``.auditooor/budget_cap_exceeded.flag``
                       (provider-capacity-report consumes this flag to refuse new
                       DeepSeek dispatches.)

Anomalies are appended to ``.auditooor/deepseek_anomalies.jsonl``:
  - cost-spike:        hour cost > 5x rolling mean of prior 24 1-hour buckets
  - failure-rate-spike: failures / total > 10% in the last 100 calls
  - latency-spike:     p95 > 3x rolling baseline (median of prior 24h hour buckets)
  - tier-drift:        tier-1 emission share < 5% (Claude verification not happening)

CLI:

    python3 tools/deepseek-monitor.py \\
        --workspace /Users/wolf/auditooor-mcp \\
        --since "1h|1d|1w|2026-05-26" \\
        --provider deepseek-flash|deepseek-pro|all \\
        --task-type TOK-A|TOK-B|TOK-C|TOK-D|TOK-F|all \\
        [--watch] [--json] [--alert-threshold-usd 80] [--cap-usd 100]

Discipline:
  - Pure stdlib (no extra deps).
  - Read-only by default for log files. Side-effect writes go ONLY to:
        ``.auditooor/budget_alerts.jsonl``
        ``.auditooor/budget_cap_exceeded.flag``
        ``.auditooor/deepseek_anomalies.jsonl``
  - NEVER echoes ``DEEPSEEK_API_KEY`` or any other secret.
  - In tests, all inputs are mocked via the ``--workspace`` flag (tmpdir).

Schema id: ``auditooor.deepseek_monitor_dashboard.v1``.

<!-- r36-rebuttal: lane-DEEPSEEK-MONITORING declared in .auditooor/agent_pathspec.json -->
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_ID = "auditooor.deepseek_monitor_dashboard.v1"

# DeepSeek price card (USD per 1M tokens). Updated 2026-05-26 from public docs.
# Cache-miss = first-time prompt tokens; cache-hit = prefix already in KV cache;
# output = generated tokens. Pro/Flash differ only in price scale.
PRICE_CARD_USD_PER_M = {
    "deepseek-flash": {
        "input_cache_miss": 0.07,
        "input_cache_hit": 0.014,
        "output": 0.42,
    },
    "deepseek-pro": {
        "input_cache_miss": 0.27,
        "input_cache_hit": 0.054,
        "output": 1.08,
    },
}

TASK_TYPES = {"TOK-A", "TOK-B", "TOK-C", "TOK-D", "TOK-F"}

ANOMALY_KINDS = {
    "cost-spike",
    "failure-rate-spike",
    "latency-spike",
    "tier-drift",
}


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(d: _dt.datetime) -> str:
    return d.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_since(since: str, *, ref: _dt.datetime | None = None) -> _dt.datetime:
    """Parse '1h' / '6h' / '1d' / '1w' / '2026-05-26' / iso8601."""
    if ref is None:
        ref = _now_utc()
    s = since.strip().lower()
    if not s:
        return ref - _dt.timedelta(days=1)
    # Relative window (digits + unit).
    if len(s) >= 2 and s[:-1].isdigit() and s[-1] in {"h", "d", "w", "m"}:
        n = int(s[:-1])
        unit = s[-1]
        if unit == "h":
            return ref - _dt.timedelta(hours=n)
        if unit == "d":
            return ref - _dt.timedelta(days=n)
        if unit == "w":
            return ref - _dt.timedelta(weeks=n)
        if unit == "m":
            # 30-day approximation.
            return ref - _dt.timedelta(days=30 * n)
    # ISO date / datetime.
    try:
        if "T" in since:
            return _dt.datetime.fromisoformat(since.replace("Z", "+00:00")).astimezone(
                _dt.timezone.utc
            )
        d = _dt.datetime.strptime(since, "%Y-%m-%d")
        return d.replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        # Fall back to 1 day.
        return ref - _dt.timedelta(days=1)


def _month_start(ref: _dt.datetime) -> _dt.datetime:
    return _dt.datetime(ref.year, ref.month, 1, tzinfo=_dt.timezone.utc)


# ---------------------------------------------------------------------------
# Log loaders
# ---------------------------------------------------------------------------

DEFAULT_DISPATCH_LOG = ".auditooor/llm_dispatch_log.jsonl"
DEFAULT_FANOUT_DIR = ".auditooor/deepseek_fanout"
DEFAULT_BUDGET_ALERTS = ".auditooor/budget_alerts.jsonl"
DEFAULT_CAP_FLAG = ".auditooor/budget_cap_exceeded.flag"
DEFAULT_ANOMALIES = ".auditooor/deepseek_anomalies.jsonl"


def _iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield obj
    except OSError:
        return


def load_dispatch_rows(workspace: Path) -> list[dict[str, Any]]:
    """Load canonical dispatch log + every per-run fanout monitor.jsonl."""
    rows: list[dict[str, Any]] = []
    rows.extend(_iter_jsonl(workspace / DEFAULT_DISPATCH_LOG))
    fanout_root = workspace / DEFAULT_FANOUT_DIR
    if fanout_root.is_dir():
        for sub in sorted(fanout_root.iterdir()):
            if sub.is_dir():
                rows.extend(_iter_jsonl(sub / "monitor.jsonl"))
    return rows


# ---------------------------------------------------------------------------
# Cost / classification
# ---------------------------------------------------------------------------

def _row_ts(row: dict[str, Any]) -> _dt.datetime | None:
    ts = row.get("ts") or row.get("timestamp")
    if not ts:
        return None
    try:
        return _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(
            _dt.timezone.utc
        )
    except ValueError:
        return None


def _row_provider(row: dict[str, Any]) -> str:
    """Return canonical 'deepseek-flash' / 'deepseek-pro' / other."""
    raw = (row.get("provider") or "").strip().lower()
    if raw in PRICE_CARD_USD_PER_M:
        return raw
    model = (row.get("model") or "").strip().lower()
    if "deepseek" in model:
        if "flash" in model or "lite" in model:
            return "deepseek-flash"
        if "pro" in model or "v3" in model or "r1" in model:
            return "deepseek-pro"
        return "deepseek-flash"
    if raw == "deepseek":
        return "deepseek-flash"
    return raw or "unknown"


def _row_task_type(row: dict[str, Any]) -> str:
    tt = row.get("task_type") or row.get("role") or row.get("lane") or ""
    s = str(tt)
    for canon in TASK_TYPES:
        if canon in s:
            return canon
    return "OTHER"


def _row_outcome(row: dict[str, Any]) -> str:
    outcome = (row.get("outcome") or "").strip().lower()
    if outcome in {"ok", "success", "succeeded"}:
        return "success"
    if outcome in {"insufficient_balance", "out_of_funds", "402"}:
        return "insufficient_balance"
    if outcome in {"failed", "error", "fail", "timeout"}:
        return "failed"
    # Try success boolean.
    success = row.get("success")
    if success is True:
        return "success"
    if success is False:
        return "failed"
    return outcome or "unknown"


def _row_tokens(row: dict[str, Any]) -> dict[str, int]:
    """Tokens: cache_miss_in / cache_hit_in / out. Old schemas only give tokens_used."""
    cm = int(row.get("tokens_in_cache_miss") or row.get("prompt_tokens_cache_miss") or 0)
    ch = int(row.get("tokens_in_cache_hit") or row.get("prompt_tokens_cache_hit") or 0)
    out = int(row.get("tokens_out") or row.get("completion_tokens") or 0)
    # Legacy fallback: split tokens_used 70/30 input/output for cost approximation.
    if cm == 0 and ch == 0 and out == 0:
        total = int(row.get("tokens_used") or 0)
        if total > 0:
            cm = int(total * 0.7)
            out = total - cm
    return {"cache_miss_in": cm, "cache_hit_in": ch, "out": out}


def _row_cost_usd(row: dict[str, Any]) -> dict[str, float]:
    """Return per-row cost breakdown USD. Honors explicit ``cost_usd`` if present."""
    if "cost_usd" in row and isinstance(row["cost_usd"], (int, float)):
        return {"total": float(row["cost_usd"]), "cache_miss_in": 0.0, "cache_hit_in": 0.0, "out": 0.0}
    provider = _row_provider(row)
    card = PRICE_CARD_USD_PER_M.get(provider)
    if not card:
        return {"total": 0.0, "cache_miss_in": 0.0, "cache_hit_in": 0.0, "out": 0.0}
    tok = _row_tokens(row)
    cm = (tok["cache_miss_in"] / 1_000_000.0) * card["input_cache_miss"]
    ch = (tok["cache_hit_in"] / 1_000_000.0) * card["input_cache_hit"]
    out = (tok["out"] / 1_000_000.0) * card["output"]
    return {
        "cache_miss_in": cm,
        "cache_hit_in": ch,
        "out": out,
        "total": cm + ch + out,
    }


def _row_latency_ms(row: dict[str, Any]) -> float | None:
    for key in ("latency_ms", "latency", "duration_ms", "elapsed_ms"):
        v = row.get(key)
        if isinstance(v, (int, float)):
            return float(v)
    # seconds variants
    for key in ("latency_s", "duration_s", "elapsed_s"):
        v = row.get(key)
        if isinstance(v, (int, float)):
            return float(v) * 1000.0
    return None


def _row_verification_tier(row: dict[str, Any]) -> str:
    """Return tier-1..tier-5 if present, else 'unstated'."""
    vt = row.get("verification_tier")
    if isinstance(vt, str) and vt.startswith("tier-"):
        return vt
    return "unstated"


# ---------------------------------------------------------------------------
# Filtering + aggregation
# ---------------------------------------------------------------------------

def filter_rows(
    rows: list[dict[str, Any]],
    *,
    since: _dt.datetime,
    until: _dt.datetime | None = None,
    provider: str = "all",
    task_type: str = "all",
) -> list[dict[str, Any]]:
    until = until or _now_utc()
    out: list[dict[str, Any]] = []
    for row in rows:
        ts = _row_ts(row)
        if ts is None:
            continue
        if ts < since or ts > until:
            continue
        p = _row_provider(row)
        if provider != "all":
            if provider == "deepseek" and not p.startswith("deepseek-"):
                continue
            if provider not in {"deepseek", "all"} and p != provider:
                continue
        else:
            # default 'all' restricts to deepseek-* providers; non-deepseek rows
            # are still useful in a global view but this monitor is DeepSeek-
            # scoped, so drop other providers here.
            if not p.startswith("deepseek-"):
                continue
        if task_type != "all":
            if _row_task_type(row) != task_type:
                continue
        out.append(row)
    return out


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    calls = {"success": 0, "failed": 0, "insufficient_balance": 0, "other": 0}
    tokens = {"cache_miss_in": 0, "cache_hit_in": 0, "out": 0}
    cost = {"cache_miss_in": 0.0, "cache_hit_in": 0.0, "out": 0.0, "total": 0.0}
    latencies: list[float] = []
    tier_dist: dict[str, int] = {}
    task_breakdown: dict[str, dict[str, Any]] = {}
    provider_dist: dict[str, int] = {}

    for row in rows:
        outcome = _row_outcome(row)
        if outcome in calls:
            calls[outcome] += 1
        else:
            calls["other"] += 1
        tok = _row_tokens(row)
        tokens["cache_miss_in"] += tok["cache_miss_in"]
        tokens["cache_hit_in"] += tok["cache_hit_in"]
        tokens["out"] += tok["out"]
        c = _row_cost_usd(row)
        cost["cache_miss_in"] += c["cache_miss_in"]
        cost["cache_hit_in"] += c["cache_hit_in"]
        cost["out"] += c["out"]
        cost["total"] += c["total"]
        lat = _row_latency_ms(row)
        if lat is not None:
            latencies.append(lat)
        tier = _row_verification_tier(row)
        tier_dist[tier] = tier_dist.get(tier, 0) + 1
        prov = _row_provider(row)
        provider_dist[prov] = provider_dist.get(prov, 0) + 1
        tt = _row_task_type(row)
        sub = task_breakdown.setdefault(
            tt,
            {"calls": 0, "cost_usd": 0.0, "tokens_out": 0},
        )
        sub["calls"] += 1
        sub["cost_usd"] += c["total"]
        sub["tokens_out"] += tok["out"]

    lat_stats = {"avg": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "n": 0}
    if latencies:
        latencies_sorted = sorted(latencies)
        lat_stats = {
            "avg": statistics.fmean(latencies_sorted),
            "p50": _percentile(latencies_sorted, 50),
            "p95": _percentile(latencies_sorted, 95),
            "p99": _percentile(latencies_sorted, 99),
            "n": len(latencies_sorted),
        }
    total = sum(calls.values())
    tier1_share = (tier_dist.get("tier-1", 0) / total) if total else 0.0
    tier3_share = (tier_dist.get("tier-3", 0) / total) if total else 0.0
    fail_share = ((calls["failed"] + calls["insufficient_balance"]) / total) if total else 0.0

    return {
        "calls": calls,
        "total_calls": total,
        "tokens": tokens,
        "cost_usd": cost,
        "latency_ms": lat_stats,
        "verification_tier_dist": tier_dist,
        "tier1_share": tier1_share,
        "tier3_share": tier3_share,
        "failure_share": fail_share,
        "task_type_breakdown": task_breakdown,
        "provider_breakdown": provider_dist,
    }


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * pct / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _hour_buckets(rows: list[dict[str, Any]], *, ref: _dt.datetime) -> dict[str, dict[str, float]]:
    """Return {hour-iso: {cost_usd, calls, p95_latency_ms, failures}}."""
    buckets: dict[str, dict[str, Any]] = {}
    bucket_latencies: dict[str, list[float]] = {}
    for row in rows:
        ts = _row_ts(row)
        if ts is None:
            continue
        key = ts.replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
        b = buckets.setdefault(key, {"cost_usd": 0.0, "calls": 0, "failures": 0})
        b["cost_usd"] += _row_cost_usd(row)["total"]
        b["calls"] += 1
        outcome = _row_outcome(row)
        if outcome in {"failed", "insufficient_balance"}:
            b["failures"] += 1
        lat = _row_latency_ms(row)
        if lat is not None:
            bucket_latencies.setdefault(key, []).append(lat)
    for key, lats in bucket_latencies.items():
        s = sorted(lats)
        buckets[key]["p95_latency_ms"] = _percentile(s, 95)
    return buckets


def detect_anomalies(
    rows: list[dict[str, Any]],
    agg: dict[str, Any],
    *,
    ref: _dt.datetime,
) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    # 1) Cost-spike: this hour > 5x rolling-mean of prior 24h.
    hb = _hour_buckets(rows, ref=ref)
    cur_hour = ref.replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
    cur = hb.get(cur_hour, {"cost_usd": 0.0, "calls": 0, "failures": 0})
    prior_keys = sorted(k for k in hb.keys() if k < cur_hour)[-24:]
    prior_costs = [hb[k]["cost_usd"] for k in prior_keys if hb[k]["cost_usd"] > 0]
    if prior_costs and cur["cost_usd"] > 0:
        prior_mean = statistics.fmean(prior_costs)
        if prior_mean > 0 and cur["cost_usd"] > 5.0 * prior_mean:
            anomalies.append({
                "kind": "cost-spike",
                "current_hour_cost_usd": round(cur["cost_usd"], 6),
                "rolling_mean_24h_usd": round(prior_mean, 6),
                "multiple": round(cur["cost_usd"] / prior_mean, 2),
                "detected_at": _iso(ref),
            })
    # 2) Failure-rate-spike: failures/total > 10% in last 100 calls.
    sorted_rows = sorted(
        (r for r in rows if _row_ts(r) is not None),
        key=lambda r: _row_ts(r),
    )
    last100 = sorted_rows[-100:]
    if len(last100) >= 20:  # need a meaningful window
        fails = sum(1 for r in last100 if _row_outcome(r) in {"failed", "insufficient_balance"})
        rate = fails / len(last100)
        if rate > 0.10:
            anomalies.append({
                "kind": "failure-rate-spike",
                "window_n": len(last100),
                "failures": fails,
                "rate": round(rate, 4),
                "threshold": 0.10,
                "detected_at": _iso(ref),
            })
    # 3) Latency-spike: current-hour p95 > 3x baseline median(prior 24h p95).
    prior_p95 = [hb[k].get("p95_latency_ms", 0.0) for k in prior_keys if hb[k].get("p95_latency_ms", 0.0) > 0]
    cur_p95 = hb.get(cur_hour, {}).get("p95_latency_ms", 0.0)
    if prior_p95 and cur_p95 > 0:
        baseline = statistics.median(prior_p95)
        if baseline > 0 and cur_p95 > 3.0 * baseline:
            anomalies.append({
                "kind": "latency-spike",
                "current_p95_ms": round(cur_p95, 2),
                "baseline_p95_ms": round(baseline, 2),
                "multiple": round(cur_p95 / baseline, 2),
                "detected_at": _iso(ref),
            })
    # 4) Tier-drift: tier-1 share < 5% (Claude verification not happening).
    total = agg["total_calls"]
    if total >= 50:  # need a meaningful sample
        tier1_share = agg["tier1_share"]
        if tier1_share < 0.05:
            anomalies.append({
                "kind": "tier-drift",
                "tier1_share": round(tier1_share, 4),
                "threshold": 0.05,
                "total_calls": total,
                "detected_at": _iso(ref),
            })
    return anomalies


# ---------------------------------------------------------------------------
# Budget tracking
# ---------------------------------------------------------------------------

def month_to_date_spend(rows: list[dict[str, Any]], *, ref: _dt.datetime) -> float:
    start = _month_start(ref)
    total = 0.0
    for row in rows:
        ts = _row_ts(row)
        if ts is None or ts < start:
            continue
        prov = _row_provider(row)
        if not prov.startswith("deepseek-"):
            continue
        total += _row_cost_usd(row)["total"]
    return total


def evaluate_budget(
    mtd_spend_usd: float,
    *,
    cap_usd: float,
    alert_threshold_usd: float | None,
) -> dict[str, Any]:
    threshold = alert_threshold_usd if alert_threshold_usd is not None else (cap_usd * 0.80)
    pct = (mtd_spend_usd / cap_usd) if cap_usd > 0 else 0.0
    if mtd_spend_usd >= cap_usd:
        state = "EXCEEDED"
    elif mtd_spend_usd >= threshold:
        state = "WARN"
    elif cap_usd > 0 and mtd_spend_usd >= cap_usd * 0.50:
        state = "INFO"
    else:
        state = "OK"
    return {
        "state": state,
        "mtd_spend_usd": round(mtd_spend_usd, 6),
        "cap_usd": round(cap_usd, 6),
        "alert_threshold_usd": round(threshold, 6),
        "fraction_of_cap": round(pct, 4),
    }


def emit_budget_side_effects(
    workspace: Path,
    budget: dict[str, Any],
    *,
    ref: _dt.datetime,
) -> dict[str, Any]:
    """Write alert / cap-exceeded flag side-effects. Returns a manifest."""
    actions: dict[str, Any] = {"alerts_appended": [], "cap_flag_written": False, "cap_flag_cleared": False}
    state = budget["state"]
    if state == "INFO":
        # stderr-only; not persisted.
        return actions
    alert_path = workspace / DEFAULT_BUDGET_ALERTS
    cap_flag = workspace / DEFAULT_CAP_FLAG
    if state in {"WARN", "EXCEEDED"}:
        alert_path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": _iso(ref),
            "state": state,
            "mtd_spend_usd": budget["mtd_spend_usd"],
            "cap_usd": budget["cap_usd"],
            "fraction_of_cap": budget["fraction_of_cap"],
            "schema": "auditooor.deepseek_budget_alert.v1",
        }
        with alert_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        actions["alerts_appended"].append(state)
    if state == "EXCEEDED":
        cap_flag.parent.mkdir(parents=True, exist_ok=True)
        cap_flag.write_text(
            json.dumps(
                {
                    "ts": _iso(ref),
                    "mtd_spend_usd": budget["mtd_spend_usd"],
                    "cap_usd": budget["cap_usd"],
                    "schema": "auditooor.deepseek_budget_cap_flag.v1",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        actions["cap_flag_written"] = True
    elif state in {"OK", "INFO", "WARN"} and cap_flag.exists():
        # Spend dropped back below cap (e.g., month rollover) - leave for operator,
        # do NOT auto-clear; the brief says provider-capacity-report.py reads the
        # flag, so operator should manually delete after triage.
        pass
    return actions


def emit_anomaly_side_effects(
    workspace: Path,
    anomalies: list[dict[str, Any]],
) -> None:
    if not anomalies:
        return
    path = workspace / DEFAULT_ANOMALIES
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for a in anomalies:
            fh.write(json.dumps({**a, "schema": "auditooor.deepseek_anomaly.v1"}, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Dashboard build + render
# ---------------------------------------------------------------------------

def build_dashboard(
    workspace: Path,
    *,
    since: str,
    provider: str,
    task_type: str,
    cap_usd: float,
    alert_threshold_usd: float | None,
    ref: _dt.datetime | None = None,
) -> dict[str, Any]:
    ref = ref or _now_utc()
    since_dt = _parse_since(since, ref=ref)
    all_rows = load_dispatch_rows(workspace)
    rows = filter_rows(
        all_rows,
        since=since_dt,
        until=ref,
        provider=provider,
        task_type=task_type,
    )
    agg = aggregate(rows)
    anomalies = detect_anomalies(rows, agg, ref=ref)
    mtd_spend = month_to_date_spend(all_rows, ref=ref)
    budget = evaluate_budget(
        mtd_spend,
        cap_usd=cap_usd,
        alert_threshold_usd=alert_threshold_usd,
    )
    return {
        "schema": SCHEMA_ID,
        "generated_at": _iso(ref),
        "since": _iso(since_dt),
        "until": _iso(ref),
        "provider": provider,
        "task_type": task_type,
        "workspace": str(workspace),
        "aggregate": agg,
        "anomalies": anomalies,
        "budget": budget,
        "rows_considered": len(rows),
        "rows_total": len(all_rows),
    }


def render_markdown(dash: dict[str, Any]) -> str:
    agg = dash["aggregate"]
    cost = agg["cost_usd"]
    lat = agg["latency_ms"]
    budget = dash["budget"]
    lines: list[str] = []
    lines.append("# DeepSeek monitor dashboard")
    lines.append("")
    lines.append(f"Generated: {dash['generated_at']}")
    lines.append(f"Window: {dash['since']} -> {dash['until']}")
    lines.append(f"Provider: {dash['provider']}  Task-type: {dash['task_type']}")
    lines.append(f"Rows considered: {dash['rows_considered']} (of {dash['rows_total']} total in log)")
    lines.append("")
    lines.append("## Calls")
    lines.append("")
    lines.append(f"- Total: {agg['total_calls']}")
    for k, v in agg["calls"].items():
        lines.append(f"  - {k}: {v}")
    lines.append("")
    lines.append("## Tokens")
    lines.append("")
    lines.append(f"- Cache-miss IN: {agg['tokens']['cache_miss_in']}")
    lines.append(f"- Cache-hit IN:  {agg['tokens']['cache_hit_in']}")
    lines.append(f"- OUT:           {agg['tokens']['out']}")
    lines.append("")
    lines.append("## Cost (USD)")
    lines.append("")
    lines.append(f"- Cache-miss IN: ${cost['cache_miss_in']:.6f}")
    lines.append(f"- Cache-hit IN:  ${cost['cache_hit_in']:.6f}")
    lines.append(f"- OUT:           ${cost['out']:.6f}")
    lines.append(f"- **Total:       ${cost['total']:.6f}**")
    lines.append("")
    lines.append("## Latency (ms)")
    lines.append("")
    lines.append(f"- n={lat['n']}  avg={lat['avg']:.1f}  p50={lat['p50']:.1f}  p95={lat['p95']:.1f}  p99={lat['p99']:.1f}")
    lines.append("")
    lines.append("## Verification-tier distribution (Rule 37)")
    lines.append("")
    for tier, n in sorted(agg["verification_tier_dist"].items()):
        share = (n / agg["total_calls"]) if agg["total_calls"] else 0.0
        lines.append(f"- {tier}: {n} ({share*100:.1f}%)")
    lines.append(f"- tier-1 share: {agg['tier1_share']*100:.1f}%  tier-3 share: {agg['tier3_share']*100:.1f}%")
    lines.append("")
    lines.append("## Provider breakdown")
    lines.append("")
    for p, n in sorted(agg["provider_breakdown"].items()):
        lines.append(f"- {p}: {n}")
    lines.append("")
    lines.append("## Task-type breakdown")
    lines.append("")
    if agg["task_type_breakdown"]:
        lines.append("| Task type | Calls | Cost USD | Tokens OUT |")
        lines.append("|---|---|---|---|")
        for tt, sub in sorted(agg["task_type_breakdown"].items()):
            lines.append(f"| {tt} | {sub['calls']} | ${sub['cost_usd']:.6f} | {sub['tokens_out']} |")
    else:
        lines.append("- no rows in window.")
    lines.append("")
    lines.append("## Anomalies")
    lines.append("")
    if dash["anomalies"]:
        for a in dash["anomalies"]:
            lines.append(f"- {a['kind']}: {json.dumps({k: v for k, v in a.items() if k != 'kind'}, sort_keys=True)}")
    else:
        lines.append("- none detected.")
    lines.append("")
    lines.append("## Budget (MTD)")
    lines.append("")
    lines.append(f"- State: **{budget['state']}**")
    lines.append(f"- MTD spend: ${budget['mtd_spend_usd']:.6f}")
    lines.append(f"- Cap: ${budget['cap_usd']:.6f}")
    lines.append(f"- Alert threshold: ${budget['alert_threshold_usd']:.6f}")
    lines.append(f"- Fraction of cap: {budget['fraction_of_cap']*100:.2f}%")
    lines.append("")
    return "\n".join(lines)


def emit_budget_stderr(budget: dict[str, Any]) -> None:
    state = budget["state"]
    if state == "OK":
        return
    msg_map = {
        "INFO": "[deepseek-monitor] INFO: MTD spend reached 50% of cap (${:.4f} / ${:.4f}).".format(
            budget["mtd_spend_usd"], budget["cap_usd"]
        ),
        "WARN": "[deepseek-monitor] WARN: MTD spend reached >=80% of cap (${:.4f} / ${:.4f}). Alert row appended.".format(
            budget["mtd_spend_usd"], budget["cap_usd"]
        ),
        "EXCEEDED": "[deepseek-monitor] EXCEEDED: MTD spend reached 100% of cap (${:.4f} / ${:.4f}). budget_cap_exceeded.flag written. provider-capacity-report.py will refuse new DeepSeek dispatches until cleared.".format(
            budget["mtd_spend_usd"], budget["cap_usd"]
        ),
    }
    msg = msg_map.get(state)
    if msg:
        sys.stderr.write(msg + "\n")


def emit_anomaly_stderr(anomalies: list[dict[str, Any]]) -> None:
    for a in anomalies:
        sys.stderr.write(f"[deepseek-monitor] WARN anomaly={a['kind']} detail={json.dumps(a, sort_keys=True)}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    ap.add_argument("--workspace", required=True, help="path to auditooor workspace root.")
    ap.add_argument("--since", default="1d", help="window: 1h, 6h, 1d, 1w, 2026-05-26.")
    ap.add_argument(
        "--provider",
        default="all",
        choices=["all", "deepseek", "deepseek-flash", "deepseek-pro"],
    )
    ap.add_argument(
        "--task-type",
        default="all",
        choices=["all"] + sorted(TASK_TYPES) + ["OTHER"],
    )
    ap.add_argument("--watch", action="store_true", help="poll loop every --watch-interval seconds.")
    ap.add_argument("--watch-interval", type=int, default=5)
    ap.add_argument("--json", action="store_true", help="emit JSON only.")
    ap.add_argument("--alert-threshold-usd", type=float, default=80.0)
    ap.add_argument("--cap-usd", type=float, default=100.0)
    ap.add_argument(
        "--no-side-effects",
        action="store_true",
        help="do not write budget_alerts.jsonl / cap-exceeded flag / anomalies log.",
    )
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        sys.stderr.write(f"[deepseek-monitor] workspace not a directory: {workspace}\n")
        return 1

    def _once() -> dict[str, Any]:
        dash = build_dashboard(
            workspace,
            since=args.since,
            provider=args.provider,
            task_type=args.task_type,
            cap_usd=args.cap_usd,
            alert_threshold_usd=args.alert_threshold_usd,
        )
        if not args.no_side_effects:
            emit_budget_side_effects(workspace, dash["budget"], ref=_now_utc())
            emit_anomaly_side_effects(workspace, dash["anomalies"])
        emit_budget_stderr(dash["budget"])
        emit_anomaly_stderr(dash["anomalies"])
        if args.json:
            sys.stdout.write(json.dumps(dash, sort_keys=True, indent=2) + "\n")
        else:
            sys.stdout.write(render_markdown(dash) + "\n")
        sys.stdout.flush()
        return dash

    if not args.watch:
        _once()
        return 0
    try:
        while True:
            _once()
            time.sleep(max(1, args.watch_interval))
    except KeyboardInterrupt:
        sys.stderr.write("[deepseek-monitor] watch interrupted\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
