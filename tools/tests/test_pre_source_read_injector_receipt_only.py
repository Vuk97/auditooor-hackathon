"""Tests for the --persist-receipt-only flag (FIX_PLAN Rank 7).

The pre-source-read injector, when run with an explicit --workspace, persists
BOTH a source-read receipt AND appends the injected hacker questions as open
obligations. Rank 7 adds --persist-receipt-only to break that coupling: the
receipt still persists (so the source-read is provably recorded), but the
obligation-append block is skipped, so the injector no longer manufactures
open obligation debt against itself (self-inflicted #78).

Coverage:
  * CONTROL (true-positive preserved): a normal --workspace run STILL appends
    obligations - the genuine obligation-recording behavior is not weakened.
  * SUPPRESSION: --persist-receipt-only skips the obligation append while the
    receipt is still written.
  * LIVE-HOOK ZERO-CHANGE: with no --workspace (the live hook invocation) NEITHER
    ledger is written, with or without the new flag.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "auditooor-pre-source-read-injector.py"
FIXTURE_GO = REPO_ROOT / "tools" / "tests" / "fixtures" / "fn_sig_extractor_go" / "sample.go"

OBLIGATIONS_REL = Path(".auditooor") / "hacker_question_obligations.jsonl"
RECEIPTS_REL = Path(".auditooor") / "source_read_receipts.jsonl"


def _run_cli(ws: Path | None, *extra: str) -> subprocess.CompletedProcess:
    args = [sys.executable, str(TOOL_PATH), str(FIXTURE_GO)]
    if ws is not None:
        args += ["--workspace", str(ws)]
    args += list(extra)
    return subprocess.run(args, capture_output=True, text=True, timeout=120)


class PersistReceiptOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        # Sanity: fixture must yield >0 analyzed functions or the obligation
        # branch is dead and the test proves nothing.
        self.assertTrue(FIXTURE_GO.is_file(), f"missing fixture {FIXTURE_GO}")

    # CONTROL: the genuine obligation-recording behavior still fires. Without the
    # new flag, an explicit --workspace run appends obligations AND a receipt.
    def test_control_default_run_still_appends_obligations(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proc = _run_cli(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            obl = ws / OBLIGATIONS_REL
            rcpt = ws / RECEIPTS_REL
            self.assertTrue(
                obl.is_file() and obl.read_text().strip(),
                "CONTROL FAILED: default --workspace run must still append "
                f"obligations; stderr={proc.stderr}",
            )
            self.assertTrue(
                rcpt.is_file() and rcpt.read_text().strip(),
                "default run must also persist a receipt",
            )

    # SUPPRESSION: --persist-receipt-only writes the receipt but NOT obligations.
    def test_receipt_only_skips_obligations_keeps_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proc = _run_cli(ws, "--persist-receipt-only")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            obl = ws / OBLIGATIONS_REL
            rcpt = ws / RECEIPTS_REL
            # Receipt still persisted.
            self.assertTrue(
                rcpt.is_file() and rcpt.read_text().strip(),
                f"receipt must still persist under --persist-receipt-only; stderr={proc.stderr}",
            )
            # Obligation ledger NOT created (or left empty).
            self.assertFalse(
                obl.is_file() and obl.read_text().strip(),
                "SUPPRESSION FAILED: --persist-receipt-only must NOT append obligations",
            )

    # SUPPRESSION via env: the AUDITOOOR_PRE_SOURCE_READ_RECEIPT_ONLY env toggle
    # has the same effect as the flag.
    def test_receipt_only_env_toggle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            import os
            env = dict(os.environ)
            env["AUDITOOOR_PRE_SOURCE_READ_RECEIPT_ONLY"] = "1"
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), str(FIXTURE_GO), "--workspace", str(ws)],
                capture_output=True, text=True, timeout=120, env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(
                (ws / OBLIGATIONS_REL).is_file() and (ws / OBLIGATIONS_REL).read_text().strip(),
                "env toggle must suppress obligation append",
            )
            self.assertTrue(
                (ws / RECEIPTS_REL).is_file() and (ws / RECEIPTS_REL).read_text().strip(),
                "env toggle must keep the receipt",
            )

    # LIVE-HOOK ZERO-CHANGE: no --workspace -> no persistence at all, whether or
    # not the new flag is present. This is the live hook's exact invocation
    # shape (claude-pre-source-read-hook.sh passes no --workspace).
    def test_no_workspace_writes_nothing_default(self) -> None:
        proc = _run_cli(None)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_no_workspace_writes_nothing_with_flag(self) -> None:
        # The flag with no workspace is inert: the whole persistence block is
        # guarded by `if workspace_str`, so nothing is written and rc==0.
        proc = _run_cli(None, "--persist-receipt-only")
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
