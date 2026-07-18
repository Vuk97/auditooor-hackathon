"""audit-progress.py `--csv` flag unit tests.

Background — quoted from auto-improvement queue iter 2 (2026-04-25_23:25:22),
Minimax idea 1:

    File: tools/audit-progress.py
    What: Add `--csv` output flag that emits `stage,timestamp,elapsed_secs,
    status` rows. Many audits track progress in spreadsheets but the tool only
    prints human-legible progress bars to stdout.
    Success criterion: `python tools/audit-progress.py --csv --audit-id <id>`
    writes a parseable CSV ...

Kimi precheck (GAP-CONFIRMED):
    `tools/audit-progress.py` exists (223 lines) but `grep --csv` finds no
    `--csv` argument or CSV-writing logic. Directory `tests/fixtures/
    audit-progress/` does not exist.

Calibration: Kimi-grep-prechecked. Kimi has 0/3 audit-style FP rate but a
much higher rate on idea-prechecks; supervisor verified the gap by reading
the source file (no `csv`/`--format` reference) before shipping.

These tests cover the pure `render_csv` helper and `--csv PATH` CLI plumbing.
We deliberately do NOT exercise the full engage.py subprocess path (covered
by tools/tests/test_audit_orchestrator.py) — only the CSV-specific code.
"""
from __future__ import annotations

import csv
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from collections import deque
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
AUDIT_PROGRESS = REPO / "tools" / "audit-progress.py"


def _load_audit_progress_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("audit_progress", AUDIT_PROGRESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RenderCsvTest(unittest.TestCase):
    """Direct-helper tests on `render_csv`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ap = _load_audit_progress_module()

    def _make_stages(self) -> dict:
        # Mimics the `_stream_and_classify` output shape without running engage.
        return {
            "orient": {
                "started_at": 1000.0,
                "ended_at": 1032.1,
                "ended": True,
                "status": "ok",
                "tail": deque(),
            },
            "scan": {
                "started_at": 1032.5,
                "ended_at": 1037.3,
                "ended": True,
                "status": "failed",
                "tail": deque(),
            },
            "cross-ws-patterns": {
                "started_at": 1037.5,
                "ended_at": 1037.6,
                "ended": True,
                "status": "skipped",
                "tail": deque(),
            },
        }

    def test_render_csv_emits_header_and_rows(self) -> None:
        stages = self._make_stages()
        buf = io.StringIO()
        self.ap.render_csv(stages, buf)
        buf.seek(0)
        rows = list(csv.reader(buf))

        # Header must use the documented column names so spreadsheets diff
        # cleanly between runs.
        self.assertEqual(
            rows[0],
            ["stage", "status", "elapsed_secs", "started_at_epoch"],
        )

        # One data row per stage, in insertion order (matches engage.py
        # stream order).
        self.assertEqual(len(rows), 1 + 3, f"unexpected row count: {rows}")
        self.assertEqual(rows[1][0], "orient")
        self.assertEqual(rows[1][1], "ok")
        # elapsed = ended_at - started_at = 32.1
        self.assertEqual(rows[1][2], "32.1")

        self.assertEqual(rows[2][0], "scan")
        self.assertEqual(rows[2][1], "failed")
        self.assertEqual(rows[2][2], "4.8")

        self.assertEqual(rows[3][0], "cross-ws-patterns")
        self.assertEqual(rows[3][1], "skipped")
        # 0.1s rounds to "0.1" via the f"{:.1f}" format.
        self.assertEqual(rows[3][2], "0.1")

    def test_render_csv_handles_partial_metadata(self) -> None:
        """A stage that never finalized (no ended_at) must not raise; the
        CSV row simply records elapsed=0.0 against the live wall-clock
        floor. This mirrors the unterminated-stage path in
        `_finalize_unterminated`."""
        stages = {
            "weird": {
                "started_at": 0.0,
                "ended_at": None,
                "ended": False,
                "status": None,
                "tail": deque(),
            },
        }
        buf = io.StringIO()
        # Must not raise even though status is None.
        self.ap.render_csv(stages, buf)
        buf.seek(0)
        rows = list(csv.reader(buf))
        self.assertEqual(rows[0][0], "stage")
        # status column is empty string (not the literal "None").
        self.assertEqual(rows[1][0], "weird")
        self.assertEqual(rows[1][1], "")


class CliFlagTest(unittest.TestCase):
    """The `--csv` flag should be parseable; no subprocess is run."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ap = _load_audit_progress_module()

    def test_csv_flag_in_help(self) -> None:
        # argparse's --help will sys.exit(0); we capture parser directly.
        # Reach into main() to build the parser? Cheaper: inspect via spawn
        # of the script with --help.
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(AUDIT_PROGRESS), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--csv", proc.stdout)
        self.assertIn("CSV", proc.stdout)


if __name__ == "__main__":
    unittest.main()
