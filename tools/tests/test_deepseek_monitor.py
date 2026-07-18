"""Tests for tools/deepseek-monitor.py.

All inputs mocked via tmpdir workspace. NEVER touch real .auditooor/ logs.

<!-- r36-rebuttal: lane-DEEPSEEK-MONITORING declared in .auditooor/agent_pathspec.json -->
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MONITOR_PATH = ROOT / "tools" / "deepseek-monitor.py"


def _load_monitor():
    spec = importlib.util.spec_from_file_location("deepseek_monitor", MONITOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_monitor()


def _write_dispatch_log(workspace: Path, rows: list[dict]) -> None:
    p = workspace / M.DEFAULT_DISPATCH_LOG
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _ds_row(
    *,
    ts: dt.datetime,
    provider: str = "deepseek-flash",
    outcome: str = "success",
    cm: int = 0,
    ch: int = 0,
    out: int = 0,
    latency_ms: float | None = None,
    tier: str = "tier-3",
    task: str = "TOK-A",
) -> dict:
    r = {
        "ts": _iso(ts),
        "provider": provider,
        "outcome": outcome,
        "tokens_in_cache_miss": cm,
        "tokens_in_cache_hit": ch,
        "tokens_out": out,
        "verification_tier": tier,
        "task_type": task,
    }
    if latency_ms is not None:
        r["latency_ms"] = latency_ms
    return r


class TestCostCalculation(unittest.TestCase):
    """Case 1: mock dispatch log produces correct cost."""

    def test_known_cost_deepseek_flash(self) -> None:
        # 1M cache-miss tokens at $0.07 + 1M output at $0.42 = $0.49
        r = _ds_row(
            ts=dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc),
            provider="deepseek-flash",
            cm=1_000_000,
            out=1_000_000,
        )
        cost = M._row_cost_usd(r)
        self.assertAlmostEqual(cost["cache_miss_in"], 0.07, places=4)
        self.assertAlmostEqual(cost["out"], 0.42, places=4)
        self.assertAlmostEqual(cost["total"], 0.49, places=4)

    def test_known_cost_deepseek_pro(self) -> None:
        # 1M cache-miss tokens at $0.27 + 1M output at $1.08 = $1.35
        r = _ds_row(
            ts=dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc),
            provider="deepseek-pro",
            cm=1_000_000,
            out=1_000_000,
        )
        cost = M._row_cost_usd(r)
        self.assertAlmostEqual(cost["total"], 1.35, places=4)

    def test_dispatch_log_aggregate_cost(self) -> None:
        ref = dt.datetime(2026, 5, 26, 18, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [
                _ds_row(ts=ref - dt.timedelta(hours=1), cm=500_000, out=200_000),
                _ds_row(ts=ref - dt.timedelta(hours=2), cm=500_000, out=200_000),
            ]
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws,
                since="1d",
                provider="all",
                task_type="all",
                cap_usd=100.0,
                alert_threshold_usd=80.0,
                ref=ref,
            )
            # 1M cache-miss * 0.07 + 400k out * 0.42/1M = 0.07 + 0.168 = 0.238
            self.assertAlmostEqual(dash["aggregate"]["cost_usd"]["total"], 0.238, places=4)
            self.assertEqual(dash["aggregate"]["total_calls"], 2)


class TestBudgetAlerts(unittest.TestCase):
    """Cases 2-3: 80% alert and 100% cap-exceeded side-effects."""

    def test_warn_at_80_percent(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        # Generate cost that lands between 80% and 100% of $100 cap = $85.
        # 85 USD = 85 / 0.42 * 1M output tokens (deepseek-flash output rate).
        out_tokens = int(85 / 0.42 * 1_000_000)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [_ds_row(ts=ref - dt.timedelta(hours=1), out=out_tokens)]
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["budget"]["state"], "WARN")
            actions = M.emit_budget_side_effects(ws, dash["budget"], ref=ref)
            self.assertIn("WARN", actions["alerts_appended"])
            self.assertFalse(actions["cap_flag_written"])
            self.assertTrue((ws / M.DEFAULT_BUDGET_ALERTS).is_file())
            alert_lines = (ws / M.DEFAULT_BUDGET_ALERTS).read_text().strip().splitlines()
            self.assertEqual(len(alert_lines), 1)
            row = json.loads(alert_lines[0])
            self.assertEqual(row["state"], "WARN")

    def test_exceeded_at_100_percent(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        # 110 USD spend, $100 cap -> EXCEEDED, cap flag written.
        out_tokens = int(110 / 0.42 * 1_000_000)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [_ds_row(ts=ref - dt.timedelta(hours=1), out=out_tokens)]
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["budget"]["state"], "EXCEEDED")
            actions = M.emit_budget_side_effects(ws, dash["budget"], ref=ref)
            self.assertTrue(actions["cap_flag_written"])
            flag = (ws / M.DEFAULT_CAP_FLAG)
            self.assertTrue(flag.is_file())
            payload = json.loads(flag.read_text().strip().splitlines()[0])
            self.assertGreaterEqual(payload["mtd_spend_usd"], 100.0)

    def test_ok_below_50_percent(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Very small spend.
            rows = [_ds_row(ts=ref - dt.timedelta(hours=1), out=10_000)]
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["budget"]["state"], "OK")
            actions = M.emit_budget_side_effects(ws, dash["budget"], ref=ref)
            self.assertEqual(actions["alerts_appended"], [])
            self.assertFalse((ws / M.DEFAULT_BUDGET_ALERTS).exists())


class TestAnomalyDetection(unittest.TestCase):
    """Cases 4-5: cost-spike + failure-rate-spike detection."""

    def test_cost_spike_5x_baseline(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 30, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = []
            # 24h of baseline: 100 tokens/hr (cheap).
            for h in range(1, 25):
                rows.append(
                    _ds_row(ts=ref - dt.timedelta(hours=h), out=100)
                )
            # Current-hour: 100x baseline = clearly >5x.
            rows.append(_ds_row(ts=ref - dt.timedelta(minutes=10), out=10_000))
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="2d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            kinds = {a["kind"] for a in dash["anomalies"]}
            self.assertIn("cost-spike", kinds)

    def test_failure_rate_spike(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = []
            # 30 calls total. 6 failures = 20% > 10% threshold.
            for i in range(24):
                rows.append(_ds_row(ts=ref - dt.timedelta(minutes=i), out=1000))
            for i in range(24, 30):
                rows.append(
                    _ds_row(ts=ref - dt.timedelta(minutes=i), out=0, outcome="failed")
                )
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            kinds = {a["kind"] for a in dash["anomalies"]}
            self.assertIn("failure-rate-spike", kinds)

    def test_no_anomaly_clean_load(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = []
            for h in range(1, 25):
                rows.append(_ds_row(ts=ref - dt.timedelta(hours=h), out=1000))
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="2d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["anomalies"], [])


class TestWindowFiltering(unittest.TestCase):
    """Case 6: --since 1h windows correctly."""

    def test_since_1h_filters_older_rows(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [
                _ds_row(ts=ref - dt.timedelta(minutes=30), out=1000),  # in window
                _ds_row(ts=ref - dt.timedelta(hours=2), out=1000),     # out
                _ds_row(ts=ref - dt.timedelta(days=2), out=1000),      # out
            ]
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["rows_considered"], 1)
            self.assertEqual(dash["aggregate"]["total_calls"], 1)


class TestTaskTypeFilter(unittest.TestCase):
    """Case 7: --task-type filter."""

    def test_task_type_filter_isolates_one_type(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [
                _ds_row(ts=ref - dt.timedelta(minutes=5), out=1000, task="TOK-A"),
                _ds_row(ts=ref - dt.timedelta(minutes=10), out=1000, task="TOK-B"),
                _ds_row(ts=ref - dt.timedelta(minutes=15), out=1000, task="TOK-C"),
            ]
            _write_dispatch_log(ws, rows)
            dash_a = M.build_dashboard(
                ws, since="1h", provider="all", task_type="TOK-A",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash_a["rows_considered"], 1)
            dash_all = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash_all["rows_considered"], 3)


class TestProviderFilter(unittest.TestCase):
    """Case 8: --provider deepseek-flash isolates from deepseek-pro."""

    def test_provider_filter(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [
                _ds_row(ts=ref - dt.timedelta(minutes=5), out=1000, provider="deepseek-flash"),
                _ds_row(ts=ref - dt.timedelta(minutes=10), out=1000, provider="deepseek-pro"),
            ]
            _write_dispatch_log(ws, rows)
            dash_flash = M.build_dashboard(
                ws, since="1h", provider="deepseek-flash", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash_flash["rows_considered"], 1)
            self.assertIn("deepseek-flash", dash_flash["aggregate"]["provider_breakdown"])
            self.assertNotIn("deepseek-pro", dash_flash["aggregate"]["provider_breakdown"])


class TestTierDistribution(unittest.TestCase):
    """Case 9: verification-tier distribution + tier-drift anomaly."""

    def test_tier_drift_anomaly_fires(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # 60 calls, only 1 is tier-1 (1.67% < 5% threshold).
            rows = []
            for i in range(59):
                rows.append(_ds_row(ts=ref - dt.timedelta(minutes=i + 1), out=100, tier="tier-3"))
            rows.append(_ds_row(ts=ref - dt.timedelta(minutes=60), out=100, tier="tier-1"))
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            kinds = {a["kind"] for a in dash["anomalies"]}
            self.assertIn("tier-drift", kinds)

    def test_healthy_tier_mix_no_drift(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = []
            for i in range(50):
                rows.append(_ds_row(ts=ref - dt.timedelta(minutes=i + 1), out=100, tier="tier-3"))
            for i in range(10):
                rows.append(_ds_row(ts=ref - dt.timedelta(minutes=i + 100), out=100, tier="tier-1"))
            _write_dispatch_log(ws, rows)
            dash = M.build_dashboard(
                ws, since="1d", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertGreaterEqual(dash["aggregate"]["tier1_share"], 0.10)
            kinds = {a["kind"] for a in dash["anomalies"]}
            self.assertNotIn("tier-drift", kinds)


class TestWatchInvocation(unittest.TestCase):
    """Case 10: --watch daemon loops at interval (smoke / no-side-effects)."""

    def test_watch_single_iteration(self) -> None:
        # We can't easily run a true daemon in a unit test, but we can confirm
        # the build_dashboard fn is idempotent on multiple back-to-back calls.
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            rows = [_ds_row(ts=ref - dt.timedelta(minutes=5), out=1000)]
            _write_dispatch_log(ws, rows)
            d1 = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            d2 = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(d1["rows_considered"], d2["rows_considered"])
            self.assertAlmostEqual(
                d1["aggregate"]["cost_usd"]["total"],
                d2["aggregate"]["cost_usd"]["total"],
                places=8,
            )


class TestFanoutMonitorIngestion(unittest.TestCase):
    """Case 11: per-run fanout monitor.jsonl files are also picked up."""

    def test_fanout_monitor_jsonl_loaded(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # No canonical dispatch log; only per-run fanout monitor.
            fanout = ws / ".auditooor" / "deepseek_fanout" / "run-abc123"
            fanout.mkdir(parents=True)
            with (fanout / "monitor.jsonl").open("w") as fh:
                fh.write(json.dumps(_ds_row(
                    ts=ref - dt.timedelta(minutes=5), out=1000,
                ), sort_keys=True) + "\n")
            dash = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            self.assertEqual(dash["rows_considered"], 1)


class TestParseSince(unittest.TestCase):
    """Case 12: --since parsing covers 1h, 1d, 1w, iso-date."""

    def test_relative_windows(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(M._parse_since("1h", ref=ref), ref - dt.timedelta(hours=1))
        self.assertEqual(M._parse_since("6h", ref=ref), ref - dt.timedelta(hours=6))
        self.assertEqual(M._parse_since("1d", ref=ref), ref - dt.timedelta(days=1))
        self.assertEqual(M._parse_since("1w", ref=ref), ref - dt.timedelta(weeks=1))

    def test_iso_date(self) -> None:
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        d = M._parse_since("2026-05-25", ref=ref)
        self.assertEqual(d.year, 2026)
        self.assertEqual(d.month, 5)
        self.assertEqual(d.day, 25)


class TestNoSecretLeak(unittest.TestCase):
    """Case 13: render output never contains DEEPSEEK_API_KEY contents."""

    def test_render_never_contains_api_key(self) -> None:
        # Even if a malicious row carried an api_key field, the renderer must
        # not surface it.
        ref = dt.datetime(2026, 5, 26, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = _ds_row(ts=ref - dt.timedelta(minutes=5), out=1000)
            row["api_key"] = "sk-deepseek-SECRET-DO-NOT-LEAK"
            _write_dispatch_log(ws, [row])
            dash = M.build_dashboard(
                ws, since="1h", provider="all", task_type="all",
                cap_usd=100.0, alert_threshold_usd=80.0, ref=ref,
            )
            md = M.render_markdown(dash)
            self.assertNotIn("sk-deepseek-SECRET", md)
            self.assertNotIn("api_key", md.lower())


if __name__ == "__main__":
    unittest.main()
