#!/usr/bin/env python3
"""Tests for tools/queue-staleness-report.py — P2-4 burn-down.

Covers the four shapes called out in the burn-down brief:

* empty queue       -> empty report, status set is empty
* all-fresh queue   -> every block is PASS
* mixed queue       -> WARN/FAIL appear where age crosses the threshold
* all-stale queue   -> every block is FAIL

Also covers ``REQUIRE_NO_STALE_QUEUES=1`` promoting WARN to FAIL, and the
env-configurable thresholds (``AUDITOOOR_QUEUE_WARN_DAYS`` /
``AUDITOOOR_QUEUE_FAIL_DAYS``). All hermetic — no clocks beyond the file
mtime values we set ourselves.
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
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "queue-staleness-report.py"
CLOSEOUT_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


CLOSEOUT = _load("audit_closeout_check", CLOSEOUT_PATH)
REPORT = _load("queue_staleness_report", TOOL_PATH)


# Fixed reference clock so all relative ages are deterministic. Equivalent to
# 2026-04-29T00:00:00Z, which is well after every mtime in these tests.
NOW = 1_777_708_800.0
DAY = 86400.0


def _set_mtime(path: Path, days_ago: float) -> None:
    """Set ``path`` mtime to ``NOW - days_ago * DAY``."""
    ts = NOW - days_ago * DAY
    os.utime(path, (ts, ts))


def _scaffold_brief(ws: Path, name: str, days_ago: float) -> Path:
    brief_dir = ws / "source_mining" / "run-1" / "poc_task_briefs"
    brief_dir.mkdir(parents=True, exist_ok=True)
    p = brief_dir / name
    p.write_text("# PoC Dispatch Brief\n", encoding="utf-8")
    _set_mtime(p, days_ago)
    return p


def _scaffold_deep_record(ws: Path, name: str, days_ago: float) -> Path:
    recs = ws / "deep_counterexamples"
    recs.mkdir(parents=True, exist_ok=True)
    p = recs / name
    p.write_text(
        json.dumps({
            "schema_version": "auditooor.deep_counterexample.v1",
            "engine": "halmos",
            "target_function": "Vault.withdraw",
            "expected_invariant": "shares decrease",
            "observed_violation": "shares unchanged",
            "promotes_to_poc_work": False,
        })
        + "\n",
        encoding="utf-8",
    )
    _set_mtime(p, days_ago)
    return p


def _scaffold_p1_queue(ws: Path, days_ago: float, *, with_manifest: bool = False) -> Path:
    root = ws / ".audit_logs" / "p1_fixture_extraction"
    root.mkdir(parents=True, exist_ok=True)
    q = root / "extraction_queue.json"
    q.write_text(
        json.dumps([
            {"pattern": "demo-pattern", "argv": ["python3", "tools/p1-fixture-extractor.py"]}
        ])
        + "\n",
        encoding="utf-8",
    )
    _set_mtime(q, days_ago)
    if with_manifest:
        (root / "execution_manifest.json").write_text("{}\n", encoding="utf-8")
    return q


def _scaffold_unresolved_manifest(ws: Path, days_ago: float, name: str = "cand") -> Path:
    p = ws / "poc_execution" / name / "execution_manifest.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"candidate_id": name, "final_result": "needs_human"}) + "\n",
        encoding="utf-8",
    )
    _set_mtime(p, days_ago)
    return p


def _by_queue(report: list[dict]) -> dict[str, dict]:
    return {b["queue"]: b for b in report}


class BuildReportTest(unittest.TestCase):
    """Direct tests of ``build_report`` — the pure function path."""

    def test_empty_workspace_returns_empty_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            self.assertEqual(REPORT.build_report(ws, now=NOW), [])

    def test_all_fresh_queue_classifies_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=0.5)
            _scaffold_brief(ws, "002-cand.md", days_ago=2.0)
            _scaffold_deep_record(ws, "halmos-vault.deep_counterexample.v1.json", days_ago=1.0)

            report = REPORT.build_report(ws, now=NOW)
            blocks = _by_queue(report)
            self.assertEqual(set(blocks), {"poc_task_brief", "deep_counterexample"})
            self.assertEqual(blocks["poc_task_brief"]["status"], CLOSEOUT.PASS)
            self.assertEqual(blocks["poc_task_brief"]["count"], 2)
            self.assertEqual(blocks["deep_counterexample"]["status"], CLOSEOUT.PASS)

    def test_mixed_queue_classifies_warn_and_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            # Fresh brief — PASS
            _scaffold_brief(ws, "001-fresh.md", days_ago=1.0)
            # WARN-aged brief (>= 7d, < 30d) -> queue rolls up to WARN
            _scaffold_brief(ws, "002-warn.md", days_ago=10.0)
            # FAIL-aged deep record (>= 30d) -> queue rolls up to FAIL
            _scaffold_deep_record(
                ws, "halmos-vault.deep_counterexample.v1.json", days_ago=45.0
            )
            # Stale P1 queue without manifest (also FAIL-aged)
            _scaffold_p1_queue(ws, days_ago=60.0, with_manifest=False)

            report = REPORT.build_report(ws, now=NOW)
            blocks = _by_queue(report)
            self.assertEqual(blocks["poc_task_brief"]["status"], CLOSEOUT.WARN)
            self.assertEqual(blocks["poc_task_brief"]["count"], 2)
            self.assertGreaterEqual(blocks["poc_task_brief"]["oldest_age_days"], 9.5)
            self.assertEqual(blocks["deep_counterexample"]["status"], CLOSEOUT.FAIL)
            self.assertEqual(blocks["p1_extraction_queue"]["status"], CLOSEOUT.FAIL)
            self.assertEqual(blocks["p1_extraction_queue"]["owner"], "p1-fixture-extraction")

    def test_all_stale_queue_classifies_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-old.md", days_ago=40.0)
            _scaffold_brief(ws, "002-old.md", days_ago=90.0)
            _scaffold_deep_record(
                ws, "halmos-vault.deep_counterexample.v1.json", days_ago=33.0
            )
            _scaffold_p1_queue(ws, days_ago=120.0, with_manifest=False)

            report = REPORT.build_report(ws, now=NOW)
            blocks = _by_queue(report)
            self.assertEqual(set(blocks), {
                "poc_task_brief", "deep_counterexample", "p1_extraction_queue",
            })
            for b in report:
                self.assertEqual(b["status"], CLOSEOUT.FAIL, b)

    def test_unresolved_manifest_promoted_into_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_unresolved_manifest(ws, days_ago=12.0)
            report = REPORT.build_report(ws, now=NOW)
            blocks = _by_queue(report)
            self.assertIn("unresolved_execution_manifest", blocks)
            self.assertEqual(
                blocks["unresolved_execution_manifest"]["status"], CLOSEOUT.WARN
            )
            self.assertEqual(blocks["unresolved_execution_manifest"]["count"], 1)


class EnvOverrideTest(unittest.TestCase):
    """Verify env-driven thresholds and REQUIRE_NO_STALE_QUEUES."""

    def test_custom_thresholds_change_classification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=3.0)
            # Tighten WARN to 1 day so 3d-old becomes WARN.
            with mock.patch.dict(os.environ, {
                "AUDITOOOR_QUEUE_WARN_DAYS": "1",
                "AUDITOOOR_QUEUE_FAIL_DAYS": "5",
            }):
                report = REPORT.build_report(ws, now=NOW)
            self.assertEqual(_by_queue(report)["poc_task_brief"]["status"], CLOSEOUT.WARN)

    def test_require_no_stale_queues_promotes_warn_to_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=10.0)  # WARN-aged by default
            with mock.patch.dict(os.environ, {"REQUIRE_NO_STALE_QUEUES": "1"}):
                report = REPORT.build_report(ws, now=NOW)
            self.assertEqual(_by_queue(report)["poc_task_brief"]["status"], CLOSEOUT.FAIL)

    def test_invalid_env_falls_back_to_defaults(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=10.0)
            with mock.patch.dict(os.environ, {
                "AUDITOOOR_QUEUE_WARN_DAYS": "garbage",
                "AUDITOOOR_QUEUE_FAIL_DAYS": "-5",
            }):
                report = REPORT.build_report(ws, now=NOW)
            # Default WARN=7 / FAIL=30 -> 10d-old is WARN, not PASS, not FAIL.
            self.assertEqual(_by_queue(report)["poc_task_brief"]["status"], CLOSEOUT.WARN)

    def test_inverted_env_thresholds_are_clamped(self) -> None:
        """``WARN=30 FAIL=7`` would create a dead band — closeout clamps
        FAIL up to WARN so the gate stays defined."""
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=20.0)
            with mock.patch.dict(os.environ, {
                "AUDITOOOR_QUEUE_WARN_DAYS": "30",
                "AUDITOOOR_QUEUE_FAIL_DAYS": "7",
            }):
                report = REPORT.build_report(ws, now=NOW)
            # With effective WARN=FAIL=30, a 20d-old item is still PASS.
            self.assertEqual(_by_queue(report)["poc_task_brief"]["status"], CLOSEOUT.PASS)


class CliTest(unittest.TestCase):
    """End-to-end CLI: argparse + JSON output + ``--strict`` exit code."""

    def test_cli_emits_compact_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=1.0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = REPORT.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(len(payload), 1)
            self.assertEqual(payload[0]["queue"], "poc_task_brief")
            self.assertEqual(payload[0]["status"], CLOSEOUT.PASS)

    def test_cli_pretty_indents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=1.0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = REPORT.main(["--workspace", str(ws), "--pretty"])
            self.assertEqual(rc, 0)
            self.assertIn("\n  ", buf.getvalue())

    def test_cli_strict_exits_one_on_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            # Force a FAIL-aged brief.
            _scaffold_brief(ws, "001-cand.md", days_ago=90.0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = REPORT.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc, 1)

    def test_cli_strict_exits_zero_on_no_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qsr-") as tmp:
            ws = Path(tmp)
            _scaffold_brief(ws, "001-cand.md", days_ago=1.0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = REPORT.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc, 0)

    def test_cli_missing_workspace_errors(self) -> None:
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = REPORT.main(["--workspace", "/no/such/path/ever"])
        self.assertEqual(rc, 2)
        self.assertIn("workspace not found", buf_err.getvalue())


if __name__ == "__main__":
    unittest.main()
