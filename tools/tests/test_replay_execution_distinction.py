#!/usr/bin/env python3
"""Tests for the ``replay-execution-distinction`` close-out row.

PR #526 gap 5. The legacy ``counterexample-execution`` row collapses
unreplayed records into a single bulk count. This new row makes the
"observed" vs "executed" distinction explicit and adds a cutoff
timestamp so legacy backlog never blocks closeout.

Acceptance grid covered:

  - 0 records, no cutoff             -> PASS (queue-empty)
  - 3 records, 2 replays, no cutoff  -> WARN ``observed=3 executed=2``
  - same with cutoff after all 3     -> PASS (legacy-only)
  - same with REQUIRE_REPLAY_EXECUTED=1 -> FAIL (post-cutoff observed-only)
  - 1 record fully executed          -> PASS (all-executed)
  - bad cutoff string                -> WARN, parse error surfaced

The tests are stdlib-only and hermetic via ``tempfile``.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check_for_distinction", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_closeout_check_for_distinction"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_record(
    ws: Path,
    name: str,
    *,
    target_function: str = "Vault.withdraw",
    engine: str = "medusa",
    generated_at_unix: int | None = None,
) -> Path:
    record_dir = ws / "deep_counterexamples"
    record_dir.mkdir(parents=True, exist_ok=True)
    record_path = record_dir / f"{name}.deep_counterexample.v1.json"
    payload = {
        "schema_version": "auditooor.deep_counterexample.v1",
        "engine": engine,
        "target_function": target_function,
        "expected_invariant": "shares decrease",
        "observed_violation": "shares unchanged",
        "promotes_to_poc_work": True,
    }
    if generated_at_unix is not None:
        payload["generated_at_unix"] = generated_at_unix
    record_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return record_path


def _write_manifest(
    ws: Path,
    candidate_id: str,
    *,
    final_result: str = "disproved",
    impact_assertion: str = "not_demonstrated",
) -> Path:
    out = ws / "poc_execution" / candidate_id / "execution_manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "candidate_id": candidate_id,
        "final_result": final_result,
        "impact_assertion": impact_assertion,
    }
    out.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return out


class EmptyQueueTest(unittest.TestCase):
    def test_empty_queue_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=False,
                replay_cutoff_unix=None,
            )
            self.assertEqual(row.status, MOD.PASS)
            self.assertEqual(row.detail["record_count"], 0)
            self.assertEqual(row.detail["status_value"], "queue-empty")


class ThreeObservedTwoExecutedNoCutoffTest(unittest.TestCase):
    """3 counterexamples, 2 replays, no cutoff -> WARN with concrete counts."""

    def _populate(self, ws: Path, *, observed_at: int) -> None:
        # 3 records.
        _write_record(ws, "medusa-vault-a", target_function="Vault.withdrawA",
                      generated_at_unix=observed_at)
        _write_record(ws, "medusa-vault-b", target_function="Vault.withdrawB",
                      generated_at_unix=observed_at)
        _write_record(ws, "medusa-vault-c", target_function="Vault.withdrawC",
                      generated_at_unix=observed_at)
        # 2 replays — match by record_id (filename stem).
        _write_manifest(ws, "medusa-vault-a")
        _write_manifest(ws, "medusa-vault-b")

    def test_warns_with_observed_executed_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            now = int(time.time())
            self._populate(ws, observed_at=now)
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=False,
                replay_cutoff_unix=None,
            )
            self.assertEqual(row.status, MOD.WARN, msg=row.reason)
            self.assertEqual(row.detail["record_count"], 3)
            self.assertEqual(row.detail["observed_count"], 1)
            self.assertEqual(row.detail["executed_count"], 2)
            self.assertEqual(row.detail["post_cutoff_observed_count"], 1)
            self.assertEqual(row.detail["legacy_observed_count"], 0)
            self.assertIn("observed=", row.reason)
            self.assertIn("executed=2", row.reason)
            self.assertEqual(row.detail["status_value"], "replay-not-executed")

    def test_cutoff_after_all_records_marks_them_legacy_and_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            past = int(time.time()) - 10_000
            self._populate(ws, observed_at=past)
            cutoff = int(time.time())  # well after the records
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=False,
                replay_cutoff_unix=cutoff,
            )
            self.assertEqual(row.status, MOD.PASS, msg=row.reason)
            self.assertEqual(row.detail["legacy_observed_count"], 1)
            self.assertEqual(row.detail["post_cutoff_observed_count"], 0)
            self.assertEqual(row.detail["status_value"], "legacy-only")

    def test_strict_mode_promotes_warn_to_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            now = int(time.time())
            self._populate(ws, observed_at=now)
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=True,
                replay_cutoff_unix=None,
            )
            self.assertEqual(row.status, MOD.FAIL, msg=row.reason)
            self.assertIn("--require-replay-executed", row.reason)
            self.assertIn(MOD.REQUIRE_REPLAY_EXECUTED_ENV, row.reason)
            self.assertEqual(row.detail["status_value"], "replay-not-executed")

    def test_strict_mode_with_cutoff_does_not_fail_on_legacy_only(self) -> None:
        """Strict + cutoff covering everything should remain PASS.

        Strict mode must only escalate **post-cutoff** observed-only
        records, not legacy backlog.
        """
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            past = int(time.time()) - 10_000
            self._populate(ws, observed_at=past)
            cutoff = int(time.time())
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=True,
                replay_cutoff_unix=cutoff,
            )
            self.assertEqual(row.status, MOD.PASS, msg=row.reason)


class FullyExecutedTest(unittest.TestCase):
    def test_one_record_one_manifest_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            _write_record(ws, "halmos-vault")
            _write_manifest(ws, "halmos-vault")
            row = MOD.check_replay_execution_distinction(
                ws,
                require_replay_executed=False,
                replay_cutoff_unix=None,
            )
            self.assertEqual(row.status, MOD.PASS)
            self.assertEqual(row.detail["status_value"], "all-executed")


class CutoffParsingTest(unittest.TestCase):
    def test_int_seconds_parses(self) -> None:
        unix, err = MOD._parse_replay_cutoff("1700000000")
        self.assertEqual(unix, 1700000000)
        self.assertIsNone(err)

    def test_iso_8601_parses(self) -> None:
        unix, err = MOD._parse_replay_cutoff("2026-04-29T00:00:00Z")
        self.assertIsNotNone(unix)
        self.assertIsNone(err)
        # April 2026 is well after 2024-01-01 (1704067200).
        self.assertGreater(unix or 0, 1704067200)

    def test_garbage_surfaces_parse_error(self) -> None:
        unix, err = MOD._parse_replay_cutoff("not a date")
        self.assertIsNone(unix)
        self.assertIsNotNone(err)

    def test_blank_returns_no_cutoff(self) -> None:
        self.assertEqual(MOD._parse_replay_cutoff(None), (None, None))
        self.assertEqual(MOD._parse_replay_cutoff(""), (None, None))
        self.assertEqual(MOD._parse_replay_cutoff("   "), (None, None))


class CliEndToEndTest(unittest.TestCase):
    """Spot-check the CLI plumbing wires the new flag and env var."""

    def _populate(self, ws: Path, *, observed_at: int) -> None:
        _write_record(ws, "medusa-x", target_function="X.bad",
                      generated_at_unix=observed_at)
        _write_record(ws, "medusa-y", target_function="Y.bad",
                      generated_at_unix=observed_at)
        _write_record(ws, "medusa-z", target_function="Z.bad",
                      generated_at_unix=observed_at)
        _write_manifest(ws, "medusa-x")
        _write_manifest(ws, "medusa-y")

    def test_strict_env_yields_nonzero_rc(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            now = int(time.time())
            self._populate(ws, observed_at=now)
            saved_strict = os.environ.get(MOD.REQUIRE_REPLAY_EXECUTED_ENV)
            saved_after = os.environ.get(MOD.REQUIRE_REPLAY_AFTER_ENV)
            try:
                os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = "1"
                os.environ.pop(MOD.REQUIRE_REPLAY_AFTER_ENV, None)
                buf = io.StringIO()
                err = io.StringIO()
                with redirect_stdout(buf), redirect_stderr(err):
                    rc = MOD.main(["--workspace", str(ws)])
                self.assertNotEqual(rc, 0,
                                    f"rc={rc}\nout={buf.getvalue()}\nerr={err.getvalue()}")
                self.assertIn("replay-execution-distinction", buf.getvalue())
            finally:
                if saved_strict is None:
                    os.environ.pop(MOD.REQUIRE_REPLAY_EXECUTED_ENV, None)
                else:
                    os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = saved_strict
                if saved_after is None:
                    os.environ.pop(MOD.REQUIRE_REPLAY_AFTER_ENV, None)
                else:
                    os.environ[MOD.REQUIRE_REPLAY_AFTER_ENV] = saved_after

    def test_replay_after_env_makes_legacy_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aco-rxd-") as tmp:
            ws = Path(tmp)
            past = int(time.time()) - 10_000
            self._populate(ws, observed_at=past)
            saved_strict = os.environ.get(MOD.REQUIRE_REPLAY_EXECUTED_ENV)
            saved_after = os.environ.get(MOD.REQUIRE_REPLAY_AFTER_ENV)
            try:
                os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = "1"
                os.environ[MOD.REQUIRE_REPLAY_AFTER_ENV] = str(int(time.time()))
                buf = io.StringIO()
                err = io.StringIO()
                with redirect_stdout(buf), redirect_stderr(err):
                    rc = MOD.main(["--workspace", str(ws)])
                # Legacy backlog only -> replay-execution-distinction
                # row stays PASS even under strict mode. Other rows in
                # an empty workspace still FAIL (canonical-audit etc.),
                # so we cannot assert rc==0 here; we only assert the
                # new row reports PASS.
                output = buf.getvalue()
                self.assertIn("replay-execution-distinction", output)
                row_line = next(
                    line for line in output.splitlines()
                    if "replay-execution-distinction" in line
                )
                self.assertIn("[PASS]", row_line, msg=row_line)
                # rc may be 0 or 1 depending on unrelated rows; what
                # matters is that the new row alone never flipped to
                # FAIL when only legacy backlog is present. Done above.
                _ = rc, err
            finally:
                if saved_strict is None:
                    os.environ.pop(MOD.REQUIRE_REPLAY_EXECUTED_ENV, None)
                else:
                    os.environ[MOD.REQUIRE_REPLAY_EXECUTED_ENV] = saved_strict
                if saved_after is None:
                    os.environ.pop(MOD.REQUIRE_REPLAY_AFTER_ENV, None)
                else:
                    os.environ[MOD.REQUIRE_REPLAY_AFTER_ENV] = saved_after


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
