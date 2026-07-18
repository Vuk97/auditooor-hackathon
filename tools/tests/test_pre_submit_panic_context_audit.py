#!/usr/bin/env python3
"""Regression coverage for pre-submit panic-context audit."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _workspace(root: Path) -> Path:
    ws = root / "audits" / "demo"
    (ws / "submissions" / "paste_ready").mkdir(parents=True)
    return ws


def _run(draft: Path, ws: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(ws.parent)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


def _base(extra: str = "") -> str:
    return textwrap.dedent(
        f"""
        # Panic in consensus path leads to validator halt

        **Severity:** High
        **Rubric:** Network-level liveness failure.
        **Dollar impact:** validator halt.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level liveness bug.

        ## Impact

        Non-self impact demonstrated: attacker transaction halts validators that the attacker does not control.

        ## Impact Contract

        - Victim: validator set
        - Source proof: protocol/app/app.go:100-180
        - Harness scaffold: poc-tests/consensus/panic_test.go
        - selected_impact: Network-level liveness failure
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: RPC-only path excluded
        - stop_condition: stop if production path no longer panics

        {extra}
        """
    ).strip() + "\n"


class PreSubmitPanicContextTests(unittest.TestCase):
    def test_panic_context_teardown_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base("Validator halt panic: context canceled during t.Cleanup after db.Close()."),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("70. PANIC-CONTEXT-AUDIT blocked", proc.stdout, proc.stdout)
            self.assertIn("fail-teardown-contaminated-panic", proc.stdout, proc.stdout)

    def test_panic_context_stable_dump_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base(
                    "Validator halt panic: unlock of unlocked mutex.\n"
                    "Stable goroutine dump captured before cleanup shows no progress for 30s."
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("70. PANIC-CONTEXT-AUDIT:", proc.stdout, proc.stdout)
            self.assertIn("pass-stable-panic-evidence", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
