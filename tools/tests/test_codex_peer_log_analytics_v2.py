#!/usr/bin/env python3
"""capability-v3 iter-v3-9 T3 — codex-peer-log-analytics v2 regression tests.

Extends the iter-v3-8 T2 + FIX-8A suite (``test_peer_log_analytics.py``)
with five tests that lock v2 contract:

1. V1 JSON keys byte-for-byte identical to the iter-v3-8 T2 baseline
   (modulo the new top-level ``v2`` key, which is stripped before
   comparison).
2. Rate-limit events count correctly off body-preview needles.
3. Rate-limit events break down by author.
4. Event-rate trend direction is ``"up"`` when the trailing slope is
   positive.
5. Event-rate trend direction honest-zeroes to ``"unknown"`` when the
   trailing window has fewer than 3 ticks.

Hermetic: no live log, no network, no ``gh``/``git``. All input comes
from the 3 v2 fixtures at
``tools/tests/fixtures/peer_log_analytics_v2/`` or from inline strings.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "codex-peer-log-analytics.py"
V1_FIXTURE_PATH = (
    ROOT / "tools" / "tests" / "fixtures" / "peer_log_analytics" / "sample_log.md"
)
V2_FIXTURE_DIR = (
    ROOT / "tools" / "tests" / "fixtures" / "peer_log_analytics_v2"
)


def _load_tool():
    """Load codex-peer-log-analytics.py as a module.

    Mirrors the loader in ``test_peer_log_analytics.py``.
    """
    spec = importlib.util.spec_from_file_location(
        "codex_peer_log_analytics", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class V1BackCompatTests(unittest.TestCase):
    """Ensures iter-v3-9 T3 does not regress iter-v3-8 T2 + FIX-8A output."""

    # Byte-for-byte snapshot of iter-v3-8 T2 + FIX-8A JSON output on
    # ``sample_log.md`` (the fixture used by
    # ``test_peer_log_analytics.py::ParseFixtureTests``). Generated
    # from the baseline tool before the v2 extension and asserted
    # unchanged here — any drift in the v1 keys will surface as a
    # string diff rather than a silent JSON-shape change.
    V1_BASELINE_FIXTURE_JSON = (
        "{\n"
        '  "by_author": {\n'
        '    "Vuk97": 3\n'
        "  },\n"
        '  "by_class": {\n'
        '    "commit-push": 0,\n'
        '    "new-pr": 0,\n'
        '    "new-task-proposal": 0,\n'
        '    "question": 1,\n'
        '    "review-feedback": 1,\n'
        '    "suggestion": 1,\n'
        '    "unclassified": 0\n'
        "  },\n"
        '  "by_route": {\n'
        '    "address-next-tick": 1,\n'
        '    "clarify": 1,\n'
        '    "file-as-T-candidate": 1\n'
        "  },\n"
        '  "events_per_tick": {\n'
        '    "max": 3,\n'
        '    "mean": 1.0,\n'
        '    "median": 0,\n'
        '    "min": 0\n'
        "  },\n"
        '  "honest_zero_ticks": 1,\n'
        '  "parse_warnings": 0,\n'
        '  "ticks": 3,\n'
        '  "time_span": {\n'
        '    "first_tick": "2026-04-24T10:00:00Z",\n'
        '    "last_tick": "2026-04-24T12:00:00Z"\n'
        "  },\n"
        '  "total_events": 3\n'
        "}"
    )

    def test_v1_keys_unchanged_byte_for_byte(self) -> None:
        """Strip the v2 key and compare to the iter-v3-8 T2 baseline.

        The tool's JSON output with the ``v2`` key removed must be
        byte-for-byte identical (same indent, key order, types) to the
        iter-v3-8 T2 + FIX-8A baseline embedded above. This locks
        back-compat for any downstream consumer that was pinned to the
        v1 schema.
        """
        mod = _load_tool()
        text = V1_FIXTURE_PATH.read_text(encoding="utf-8")
        summary = mod.analyze(text)

        # Strip v2 before serialising with the same format the CLI uses.
        self.assertIn("v2", summary, "v2 key must be present after T3 extend")
        stripped = {k: v for k, v in summary.items() if k != "v2"}
        rendered = json.dumps(stripped, indent=2, sort_keys=True)

        self.assertEqual(
            rendered,
            self.V1_BASELINE_FIXTURE_JSON,
            "v1 JSON (minus v2) drifted from iter-v3-8 T2 baseline",
        )


class RateLimitEventsTests(unittest.TestCase):
    """v2.rate_limit_events — body-preview substring matching."""

    def test_rate_limit_events_counted_in_body_preview(self) -> None:
        """Fixture: 2 previews with ``rate limit`` + 1 with ``429 Too Many``.

        The 4th row has no rate-limit language and must NOT count, to
        prove the filter is substring-on-preview and not a blanket
        everything-counts over the table.
        """
        mod = _load_tool()
        text = (V2_FIXTURE_DIR / "rate_limit_spike.md").read_text(encoding="utf-8")
        summary = mod.analyze(text)

        self.assertEqual(summary["ticks"], 1)
        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(
            summary["v2"]["rate_limit_events"],
            3,
            "2× 'rate limit' + 1× '429 Too Many' = 3 hits; 1 unrelated row must not count",
        )


class RateLimitByAuthorTests(unittest.TestCase):
    """v2.rate_limit_by_author — per-author aggregation."""

    def test_rate_limit_by_author_aggregation(self) -> None:
        """Fixture has Vuk97 × 2 rate-limit hits + peer-bot × 1."""
        mod = _load_tool()
        text = (V2_FIXTURE_DIR / "rate_limit_spike.md").read_text(encoding="utf-8")
        summary = mod.analyze(text)

        by_author = summary["v2"]["rate_limit_by_author"]
        self.assertEqual(by_author.get("Vuk97"), 2)
        self.assertEqual(by_author.get("peer-bot"), 1)
        # No other authors should appear.
        self.assertEqual(set(by_author.keys()), {"Vuk97", "peer-bot"})
        # Sum must match the headline count (defence against
        # double-counting bugs in _row_is_rate_limit).
        self.assertEqual(sum(by_author.values()), summary["v2"]["rate_limit_events"])


class EventRateTrendUpTests(unittest.TestCase):
    """v2.event_rate_trend.direction == 'up' for monotonically increasing ticks."""

    def test_event_rate_trend_direction_up_when_slope_positive(self) -> None:
        """Fixture ticks have event counts [5, 7, 9, 12].

        Least-squares slope of y=[5,7,9,12] on x=[0,1,2,3] is 2.3 —
        well above the flat threshold of 0.5, so ``direction == 'up'``
        and ``slope_per_tick > 0.5``.
        """
        mod = _load_tool()
        text = (V2_FIXTURE_DIR / "trend_up.md").read_text(encoding="utf-8")
        summary = mod.analyze(text)

        trend = summary["v2"]["event_rate_trend"]
        self.assertEqual(trend["direction"], "up")
        self.assertGreater(trend["slope_per_tick"], 0.5)
        self.assertEqual(trend["window_ticks"], 4)


class EventRateTrendShortWindowTests(unittest.TestCase):
    """Honest-zero for windows shorter than the 3-tick minimum."""

    def test_event_rate_trend_unknown_when_window_lt_3(self) -> None:
        """Fixture has exactly 2 ticks — below the 3-tick minimum.

        The trend must honest-zero to ``direction == 'unknown'`` with
        ``window_ticks == 2`` and ``slope_per_tick == 0.0`` (no
        regression attempted).
        """
        mod = _load_tool()
        text = (V2_FIXTURE_DIR / "two_tick_short_window.md").read_text(encoding="utf-8")
        summary = mod.analyze(text)

        self.assertEqual(summary["ticks"], 2)
        trend = summary["v2"]["event_rate_trend"]
        self.assertEqual(
            trend["direction"],
            "unknown",
            "window_ticks < 3 must honest-zero direction to 'unknown'",
        )
        self.assertEqual(trend["window_ticks"], 2)
        self.assertEqual(trend["slope_per_tick"], 0.0)


if __name__ == "__main__":
    unittest.main()
