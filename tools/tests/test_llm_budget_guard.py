"""Hermetic tests for tools/llm-budget-guard.py.

Coverage (10 cases):

- config validation (missing fields, bad types) -> raises ValueError
- log entry validation (missing fields) -> raises ValueError
- record_call rejects unknown provider (typo guard)
- window_status with empty log -> clean state
- window-rolling math: entries outside window roll off
- exhaustion via max_calls
- exhaustion via max_tokens
- may_call returns (False, reason) when exhausted
- soft-limit / graceful-exit signal at soft_ratio
- reset() floor excludes prior in-window entries

Test fixtures use neutral provider names ("kimi", "foo") and constructed
timestamps — NOT real session content — so this file is comment-leak-safe.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "llm-budget-guard.py"


def _load_module():
    cache_key = "_test_llm_budget_guard"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


def _write_config(
    path: Path,
    *,
    window_minutes: int = 60,
    max_calls: int = 5,
    max_tokens: int = 1000,
    soft_ratio: float = 0.8,
) -> None:
    path.write_text(
        json.dumps({
            "providers": {
                "kimi": {
                    "window_minutes": window_minutes,
                    "max_calls": max_calls,
                    "max_tokens": max_tokens,
                    "soft_ratio": soft_ratio,
                },
            },
        }),
        encoding="utf-8",
    )


def _frozen_now(when: datetime):
    """Return a now_fn closure that always reports `when`."""
    def _now():
        return when.astimezone(timezone.utc) if when.tzinfo else \
            when.replace(tzinfo=timezone.utc)
    return _now


class _Tmp:
    """Per-test scratch dir holding a config + log path pair."""

    def __init__(self) -> None:
        self._td = TemporaryDirectory()
        self.dir = Path(self._td.name)
        self.config = self.dir / "llm_budget.json"
        self.log = self.dir / "llm_budget_log.jsonl"

    def cleanup(self) -> None:
        self._td.cleanup()


class TestConfigValidation(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_required_field_rejected(self):
        # Missing max_tokens -> ValueError naming the field.
        self.tmp.config.write_text(
            json.dumps({
                "providers": {
                    "kimi": {"window_minutes": 60, "max_calls": 30},
                },
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "max_tokens"):
            self.mod.load_config(self.tmp.config)

    def test_non_positive_max_calls_rejected(self):
        self.tmp.config.write_text(
            json.dumps({
                "providers": {
                    "kimi": {
                        "window_minutes": 60,
                        "max_calls": 0,
                        "max_tokens": 1000,
                    },
                },
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "max_calls must be int > 0"):
            self.mod.load_config(self.tmp.config)

    def test_env_budget_config_override_loads_paid_profile(self):
        alt = self.tmp.dir / "paid-tier.json"
        _write_config(alt, max_calls=180, max_tokens=1_800_000,
                      soft_ratio=0.9)
        old = os.environ.get(self.mod.BUDGET_CONFIG_ENV_VAR)
        os.environ[self.mod.BUDGET_CONFIG_ENV_VAR] = str(alt)
        try:
            cfg = self.mod.load_config()
            guard = self.mod.LlmBudgetGuard(log_path=self.tmp.log)
        finally:
            if old is None:
                os.environ.pop(self.mod.BUDGET_CONFIG_ENV_VAR, None)
            else:
                os.environ[self.mod.BUDGET_CONFIG_ENV_VAR] = old
        self.assertEqual(cfg["kimi"].max_calls, 180)
        self.assertEqual(guard.budget_for("kimi").max_tokens, 1_800_000)


class TestLogEntryValidation(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()

    def test_missing_provider_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "missing required field: provider"
        ):
            self.mod._validate_log_entry({
                "ts": "2026-04-25T10:00:00Z",
                "success": True,
                "tokens_used": 0,
            })

    def test_negative_tokens_rejected(self):
        with self.assertRaisesRegex(ValueError, "tokens_used"):
            self.mod._validate_log_entry({
                "ts": "2026-04-25T10:00:00Z",
                "provider": "kimi",
                "success": True,
                "tokens_used": -1,
            })


class TestRecordCallTypoGuard(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_record_call_rejects_unknown_provider(self):
        # foot-gun guard: typos like "kimii" must NOT silently pass.
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config, log_path=self.tmp.log,
        )
        with self.assertRaisesRegex(KeyError, "kimii"):
            guard.record_call("kimii", tokens_used=1)

    def test_may_call_rejects_unknown_provider(self):
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config, log_path=self.tmp.log,
        )
        with self.assertRaisesRegex(KeyError, "kimii"):
            guard.may_call("kimii")


class TestWindowStatusEmpty(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_log_clean_state(self):
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config, log_path=self.tmp.log,
        )
        st = guard.window_status("kimi")
        self.assertEqual(st["calls_used"], 0)
        self.assertEqual(st["tokens_used"], 0)
        self.assertEqual(st["calls_remaining"], 5)
        self.assertEqual(st["tokens_remaining"], 1000)
        self.assertFalse(st["exhausted"])
        self.assertFalse(st["near_soft_limit"])
        self.assertIsNone(st["oldest_in_window_ts"])


class TestWindowRolling(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config, window_minutes=60, max_calls=5)

    def tearDown(self):
        self.tmp.cleanup()

    def test_entries_outside_window_roll_off(self):
        # "Now" at t0; one call 30min ago (in window), one 90min ago (out).
        t0 = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0),
        )
        guard.record_call(
            "kimi", tokens_used=10,
            ts=self.mod._iso(t0 - timedelta(minutes=30)),
        )
        guard.record_call(
            "kimi", tokens_used=99,
            ts=self.mod._iso(t0 - timedelta(minutes=90)),
        )
        st = guard.window_status("kimi")
        # Only the in-window entry is counted.
        self.assertEqual(st["calls_used"], 1)
        self.assertEqual(st["tokens_used"], 10)


class TestExhaustionByCalls(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config, max_calls=3, max_tokens=10000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_third_call_exhausts_calls_budget(self):
        t0 = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0),
        )
        for i in range(3):
            guard.record_call(
                "kimi", tokens_used=1,
                ts=self.mod._iso(t0 - timedelta(minutes=i)),
            )
        ok, reason = guard.may_call("kimi")
        self.assertFalse(ok)
        self.assertIn("calls budget exhausted", reason)
        self.assertIn("3/3", reason)


class TestExhaustionByTokens(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config, max_calls=100, max_tokens=500)

    def tearDown(self):
        self.tmp.cleanup()

    def test_token_budget_exhaustion_blocks(self):
        t0 = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0),
        )
        guard.record_call(
            "kimi", tokens_used=500,
            ts=self.mod._iso(t0 - timedelta(minutes=1)),
        )
        ok, reason = guard.may_call("kimi")
        self.assertFalse(ok)
        self.assertIn("tokens budget exhausted", reason)


class TestSoftLimit(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        # max_calls=10, soft_ratio=0.8 -> soft trips at >= 8 calls.
        _write_config(
            self.tmp.config,
            max_calls=10,
            max_tokens=100000,
            soft_ratio=0.8,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_soft_block_kicks_in_at_ratio(self):
        t0 = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        guard = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0),
        )
        # 7 calls = 70% -> below soft threshold (0.8).
        for i in range(7):
            guard.record_call(
                "kimi", tokens_used=1,
                ts=self.mod._iso(t0 - timedelta(minutes=i)),
            )
        ok_hard, _ = guard.may_call("kimi")
        ok_soft, _ = guard.may_call("kimi", soft=True)
        self.assertTrue(ok_hard)
        self.assertTrue(ok_soft)

        # 8 calls = 80% -> at soft threshold; soft path blocks, hard ok.
        guard.record_call(
            "kimi", tokens_used=1,
            ts=self.mod._iso(t0 - timedelta(seconds=30)),
        )
        ok_hard2, _ = guard.may_call("kimi")
        ok_soft2, reason_soft = guard.may_call("kimi", soft=True)
        self.assertTrue(ok_hard2)
        self.assertFalse(ok_soft2)
        self.assertIn("near soft limit", reason_soft)


class TestResetFloor(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = _Tmp()
        _write_config(self.tmp.config, max_calls=3, max_tokens=10000)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reset_excludes_prior_calls_from_window(self):
        t0 = datetime(2026, 4, 25, 12, 0, 0, tzinfo=timezone.utc)
        # Move through time: 2 calls, then reset, then 1 call. Pre-reset
        # calls must NOT count toward the new window — but the log file
        # must still contain all three real-call entries plus the reset
        # audit row (append-only contract).
        guard1 = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0 - timedelta(minutes=10)),
        )
        guard1.record_call("kimi", tokens_used=1)
        guard1.record_call("kimi", tokens_used=1)

        guard2 = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0 - timedelta(minutes=5)),
        )
        guard2.reset("kimi", reason="test")

        guard3 = self.mod.LlmBudgetGuard(
            config_path=self.tmp.config,
            log_path=self.tmp.log,
            now_fn=_frozen_now(t0),
        )
        guard3.record_call("kimi", tokens_used=42)
        st = guard3.window_status("kimi")
        # Only the post-reset call counts.
        self.assertEqual(st["calls_used"], 1)
        self.assertEqual(st["tokens_used"], 42)
        self.assertFalse(st["exhausted"])

        # Append-only: log must still contain all 4 lines (2 calls,
        # reset, 1 call).
        lines = [
            ln for ln in self.tmp.log.read_text().splitlines() if ln.strip()
        ]
        self.assertEqual(len(lines), 4)


if __name__ == "__main__":
    unittest.main()
